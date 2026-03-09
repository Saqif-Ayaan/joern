package io.joern.dataflowengineoss.queryengine

import io.joern.dataflowengineoss.queryengine.QueryEngineStatistic.*
import io.joern.dataflowengineoss.semanticsloader.FlowSemantic
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import upickle.default.*

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardCopyOption, StandardOpenOption}
import scala.collection.mutable
import scala.util.Try

case class SanitizerDecision(
  methodFullName: String,
  fingerprint: String,
  isSanitizer: Boolean,
  validatorVersion: String,
  updatedAtEpochMs: Long
) derives ReadWriter

case class SanitizerDecisionStore(version: Int, entries: List[SanitizerDecision]) derives ReadWriter

case class ClampDiscoveryDecisionResult(
  predictedSanitizer: Option[Boolean],
  reason: String,
  semantic: Option[FlowSemantic]
)

/** Discovery and persistence for clamp sanitizer decisions on unmodeled internal methods.
  */
object ClampSanitizerDiscovery {

  private val DecisionStoreVersion = 1
  private val NumericLikeReturnTypePattern =
    """(?i).*\b(size_t|ssize_t|unsigned|signed|short|long|int|uint\d*_t|int\d*_t)\b.*""".r

  private val decisionCache = mutable.HashMap.empty[(String, String), Boolean]
  private val sidecarCache  = mutable.HashMap.empty[(String, String), SanitizerDecision]
  private var loadedSidecarPath: Option[String] = None

  def semanticForUnmodeledMethod(method: Method, config: EngineConfig): Option[FlowSemantic] = synchronized {
    decisionForUnmodeledMethod(method, config).semantic
  }

  def decisionForUnmodeledMethod(method: Method, config: EngineConfig): ClampDiscoveryDecisionResult = synchronized {
    if (!isDiscoveryCandidate(method)) {
      return ClampDiscoveryDecisionResult(
        predictedSanitizer = None,
        reason = "not_candidate",
        semantic = None
      )
    }

    QueryEngineStatistics.incrementBy(CLAMP_DISCOVERY_CANDIDATES, 1L)

    val fingerprint = BufferOverflowSanitizerValidator.methodFingerprint(method)
    val key         = (method.fullName, fingerprint)
    ensureSidecarLoaded(config.clampSanitizerDecisionCachePath)

    val inMemoryDecisionOpt = decisionCache.get(key)
    val sidecarDecisionOpt  = sidecarCache.get(key).map(_.isSanitizer)
    val cachedDecisionOpt   = inMemoryDecisionOpt.orElse(sidecarDecisionOpt)
    cachedDecisionOpt match {
      case Some(cachedDecision) =>
        QueryEngineStatistics.incrementBy(CLAMP_DISCOVERY_CACHE_HITS, 1L)
        decisionCache.update(key, cachedDecision)
        val cacheReasonPrefix = if (inMemoryDecisionOpt.nonEmpty) "cache_hit_memory" else "cache_hit_sidecar"
        val cacheReasonSuffix = if (cachedDecision) "true" else "false"
        ClampDiscoveryDecisionResult(
          predictedSanitizer = Some(cachedDecision),
          reason = s"${cacheReasonPrefix}_$cacheReasonSuffix",
          semantic = if (cachedDecision) Some(FlowSemantic.from(method.fullName, List.empty)) else None
        )
      case None =>
        val isSanitizer = BufferOverflowSanitizerValidator.isValidatedSanitizer(method)
        decisionCache.update(key, isSanitizer)
        if (isSanitizer) {
          QueryEngineStatistics.incrementBy(CLAMP_DISCOVERY_VALIDATED, 1L)
        } else {
          QueryEngineStatistics.incrementBy(CLAMP_DISCOVERY_REJECTED, 1L)
        }
        persistDecisionIfConfigured(
          method.fullName,
          fingerprint,
          isSanitizer,
          config.clampSanitizerDecisionCachePath
        )
        ClampDiscoveryDecisionResult(
          predictedSanitizer = Some(isSanitizer),
          reason = if (isSanitizer) "discovery_validated" else "discovery_rejected",
          semantic = if (isSanitizer) Some(FlowSemantic.from(method.fullName, List.empty)) else None
        )
    }
  }

  private def isDiscoveryCandidate(method: Method): Boolean = {
    val name = Option(method.name).getOrElse("")
    !method.isExternal &&
    method.start.isStub.isEmpty &&
    method.parameter.nonEmpty &&
    method.ast.isReturn.nonEmpty &&
    !isExcludedMethodName(name) &&
    hasNumericLikeReturnType(method)
  }

  private def isExcludedMethodName(name: String): Boolean = {
    name.startsWith("<operator>.") ||
    name == "<init>" ||
    name == "<clinit>" ||
    name.startsWith("~")
  }

  private def hasNumericLikeReturnType(method: Method): Boolean = {
    val returnType = Option(method.methodReturn.typeFullName).map(_.trim).getOrElse("")
    if (returnType.isEmpty) {
      false
    } else {
      val lowered = returnType.toLowerCase
      !lowered.contains("void") &&
      !lowered.contains("*") &&
      !lowered.contains("(") &&
      !lowered.contains(")") &&
      NumericLikeReturnTypePattern.pattern.matcher(returnType).matches()
    }
  }

  private def ensureSidecarLoaded(pathOpt: Option[String]): Unit = {
    if (loadedSidecarPath == pathOpt) {
      return
    }

    loadedSidecarPath = pathOpt
    sidecarCache.clear()

    pathOpt.foreach { pathString =>
      val path = Paths.get(pathString)
      if (Files.exists(path) && Files.isRegularFile(path)) {
        Try(Files.readString(path, StandardCharsets.UTF_8))
          .toOption
          .flatMap(raw => Try(read[SanitizerDecisionStore](raw)).toOption)
          .filter(_.version == DecisionStoreVersion)
          .foreach { store =>
            store.entries
              .filter(_.validatorVersion == BufferOverflowSanitizerValidator.validatorVersion)
              .filter(d => d.methodFullName.nonEmpty && d.fingerprint.nonEmpty)
              .foreach { decision =>
                sidecarCache.update((decision.methodFullName, decision.fingerprint), decision)
              }
          }
      }
    }
  }

  private def persistDecisionIfConfigured(
    methodFullName: String,
    fingerprint: String,
    isSanitizer: Boolean,
    pathOpt: Option[String]
  ): Unit = {
    pathOpt.foreach { pathString =>
      val decision = SanitizerDecision(
        methodFullName = methodFullName,
        fingerprint = fingerprint,
        isSanitizer = isSanitizer,
        validatorVersion = BufferOverflowSanitizerValidator.validatorVersion,
        updatedAtEpochMs = System.currentTimeMillis()
      )
      sidecarCache.update((methodFullName, fingerprint), decision)

      val store = SanitizerDecisionStore(
        version = DecisionStoreVersion,
        entries = sidecarCache.values.toList.sortBy(entry => (entry.methodFullName, entry.fingerprint))
      )
      val serialized = write(store, indent = 2, sortKeys = true)
      val targetPath = Paths.get(pathString)
      Try(writeAtomically(targetPath, serialized))
    }
  }

  private def writeAtomically(targetPath: Path, contents: String): Unit = {
    Option(targetPath.getParent).foreach(parent => Files.createDirectories(parent))
    val tempName = s"${targetPath.getFileName.toString}.tmp"
    val tempPath = Option(targetPath.getParent).map(_.resolve(tempName)).getOrElse(Paths.get(tempName))

    Files.writeString(
      tempPath,
      contents,
      StandardCharsets.UTF_8,
      StandardOpenOption.CREATE,
      StandardOpenOption.TRUNCATE_EXISTING,
      StandardOpenOption.WRITE
    )

    Try(
      Files.move(
        tempPath,
        targetPath,
        StandardCopyOption.ATOMIC_MOVE,
        StandardCopyOption.REPLACE_EXISTING
      )
    ).recover { case _ =>
      Files.move(tempPath, targetPath, StandardCopyOption.REPLACE_EXISTING)
    }
    ()
  }

  def resetForTests(): Unit = synchronized {
    decisionCache.clear()
    sidecarCache.clear()
    loadedSidecarPath = None
  }
}
