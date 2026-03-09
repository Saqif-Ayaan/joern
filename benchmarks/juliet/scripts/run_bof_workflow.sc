// Runs BOF query logic with configurable engine policy/discovery settings and flow mode.

@main def main(
  cpgPath: String,
  outputPath: String,
  decisionOutputPath: String = "",
  stage: String,
  configName: String,
  flowMode: String = "malloc_memcpy",
  modeledPolicy: String = "ENFORCE",
  discoveryEnabled: Boolean = false,
  discoveryCachePath: String = ""
) = {
  import io.joern.dataflowengineoss.language.*
  import io.joern.dataflowengineoss.queryengine.{
    EngineConfig,
    EngineContext,
    ModeledSanitizerValidationPolicy,
    SanitizerDecisionEvent
  }
  import io.shiftleft.semanticcpg.language.*
  import ujson.*

  import java.nio.file.{Files, Paths}
  import scala.collection.mutable.ArrayBuffer

  importCpg(cpgPath)

  val policy = modeledPolicy.toUpperCase match {
    case "WARN"  => ModeledSanitizerValidationPolicy.WARN
    case "TRUST" => ModeledSanitizerValidationPolicy.TRUST
    case _        => ModeledSanitizerValidationPolicy.ENFORCE
  }

  val cachePathOpt = Option(discoveryCachePath).map(_.trim).filter(_.nonEmpty)
  val decisionEvents = ArrayBuffer.empty[SanitizerDecisionEvent]

  val context = EngineContext(
    config = EngineConfig(
      maxCallDepth = 2,
      enableClampSanitizerAutoDiscovery = discoveryEnabled,
      clampSanitizerDecisionCachePath = cachePathOpt,
      modeledSanitizerValidationPolicy = policy,
      sanitizerDecisionRecorder = Some(event => decisionEvents += event)
    )
  )

  def compactNode(node: Expression): Obj = {
    val loc = node.location
    Obj(
      "code" -> Str(node.code),
      "line" -> Num(loc.lineNumber.getOrElse(-1)),
      "file" -> Str(loc.filename),
      "function" -> Str(loc.methodShortName)
    )
  }

  def findingsForMallocMemcpy(): Seq[Obj] = {
    val sources = cpg.method(".*malloc$").callIn.where(_.argument(1).arithmetic).l

    cpg.method("(?i)memcpy").callIn.l.flatMap { memcpyCall =>
      val filteredReachedSources = memcpyCall
        .argument(1)
        .reachableBy(sources)(using context)
        .where(_.inAssignment.target.codeExact(memcpyCall.argument(1).code))
        .whereNot(_.argument(1).codeExact(memcpyCall.argument(3).code))
        .l

      if (filteredReachedSources.isEmpty) {
        None
      } else {
        val loc = memcpyCall.location
        val traces = Arr.from(
          filteredReachedSources.take(25).map { src =>
            Arr(
              compactNode(src),
              Obj(
                "code" -> Str(memcpyCall.code),
                "line" -> Num(loc.lineNumber.getOrElse(-1)),
                "file" -> Str(loc.filename),
                "function" -> Str(loc.methodShortName)
              )
            )
          }
        )

        val fileName = Paths.get(loc.filename).getFileName.toString
        Some(
          Obj(
            "case_id" -> Str(s"${fileName}::${loc.methodShortName}"),
            "file" -> Str(loc.filename),
            "function" -> Str(loc.methodShortName),
            "sink_line" -> Num(loc.lineNumber.getOrElse(-1)),
            "sink_code" -> Str(memcpyCall.code),
            "trace" -> traces,
            "stage" -> Str(stage),
            "config" -> Str(configName)
          )
        )
      }
    }
  }

  def findingsForIntArrayIndex(): Seq[Obj] = {
    val sourceCalls = cpg.call
      .name("(?i)(fscanf|scanf|sscanf|fgets|gets|recv|read|atoi|atol|atoll|strtol|strtoul|rand)")
      .l

    cpg.call.nameExact("<operator>.indirectIndexAccess").l.flatMap { indexAccessCall =>
      val indexExprOpt = Option(indexAccessCall.argument(2)).collect { case expr: Expression => expr }
      indexExprOpt.flatMap { indexExpr =>
        val reachedSources = indexExpr.reachableBy(sourceCalls)(using context).l
        if (reachedSources.isEmpty) {
          None
        } else {
          val loc = indexAccessCall.location
          val traces = Arr.from(
            reachedSources.take(25).map { src =>
              Arr(
                compactNode(src),
                Obj(
                  "code" -> Str(indexAccessCall.code),
                  "line" -> Num(loc.lineNumber.getOrElse(-1)),
                  "file" -> Str(loc.filename),
                  "function" -> Str(loc.methodShortName)
                )
              )
            }
          )
          val fileName = Paths.get(loc.filename).getFileName.toString
          Some(
            Obj(
              "case_id" -> Str(s"${fileName}::${loc.methodShortName}"),
              "file" -> Str(loc.filename),
              "function" -> Str(loc.methodShortName),
              "sink_line" -> Num(loc.lineNumber.getOrElse(-1)),
              "sink_code" -> Str(indexAccessCall.code),
              "trace" -> traces,
              "stage" -> Str(stage),
              "config" -> Str(configName)
            )
          )
        }
      }
    }
  }

  def findingsForIntArrayIndexClampCompatible(): Seq[Obj] = {
    def unwrapAddressOf(expr: Expression): Expression = expr match {
      case call: Call if call.name == "<operator>.addressOf" =>
        Option(call.argument(1)).collect { case nested: Expression => nested }.getOrElse(expr)
      case _ =>
        expr
    }

    val returnValueSources = cpg.call
      .name("(?i)(atoi|atol|atoll|strtol|strtoul|rand|rand32)")
      .l
      .map(call => call: Expression)

    val scanfLikeOutArgSources = cpg.call
      .name("(?i)(fscanf|scanf|sscanf)")
      .argument
      .filter(_.argumentIndex > 1)
      .collectAll[Expression]
      .l
      .map(unwrapAddressOf)

    val recvReadBufferSources = cpg.call
      .name("(?i)(recv|read)")
      .argument(2)
      .collectAll[Expression]
      .l
      .map(unwrapAddressOf)

    val fgetsGetsBufferSources = cpg.call
      .name("(?i)(fgets|gets)")
      .argument(1)
      .collectAll[Expression]
      .l
      .map(unwrapAddressOf)

    val sourceExprs = (
      returnValueSources ++
        scanfLikeOutArgSources ++
        recvReadBufferSources ++
        fgetsGetsBufferSources
    ).groupBy(_.id).values.map(_.head).toList

    cpg.call.nameExact("<operator>.indirectIndexAccess").l.flatMap { indexAccessCall =>
      val indexExprOpt = Option(indexAccessCall.argument(2)).collect { case expr: Expression => expr }
      indexExprOpt.flatMap { indexExpr =>
        val reachedSources = indexExpr.reachableBy(sourceExprs)(using context).l
        if (reachedSources.isEmpty) {
          None
        } else {
          val loc = indexAccessCall.location
          val traces = Arr.from(
            reachedSources.take(25).map { src =>
              Arr(
                compactNode(src),
                Obj(
                  "code" -> Str(indexAccessCall.code),
                  "line" -> Num(loc.lineNumber.getOrElse(-1)),
                  "file" -> Str(loc.filename),
                  "function" -> Str(loc.methodShortName)
                )
              )
            }
          )
          val fileName = Paths.get(loc.filename).getFileName.toString
          Some(
            Obj(
              "case_id" -> Str(s"${fileName}::${loc.methodShortName}"),
              "file" -> Str(loc.filename),
              "function" -> Str(loc.methodShortName),
              "sink_line" -> Num(loc.lineNumber.getOrElse(-1)),
              "sink_code" -> Str(indexAccessCall.code),
              "trace" -> traces,
              "stage" -> Str(stage),
              "config" -> Str(configName)
            )
          )
        }
      }
    }
  }

  val selectedFlowMode = Option(flowMode).map(_.trim).filter(_.nonEmpty).getOrElse("malloc_memcpy")
  val findings = selectedFlowMode.toLowerCase match {
    case "int_array_index_clamp_io" => findingsForIntArrayIndexClampCompatible()
    case "int_array_index" => findingsForIntArrayIndex()
    case _                 => findingsForMallocMemcpy()
  }

  val payload = Obj(
    "stage" -> Str(stage),
    "config" -> Str(configName),
    "flow_mode" -> Str(selectedFlowMode),
    "modeled_policy" -> Str(policy.toString),
    "discovery_enabled" -> Bool(discoveryEnabled),
    "finding_count" -> Num(findings.size),
    "findings" -> Arr.from(findings)
  )

  val uniqueDecisionEvents = decisionEvents
    .groupBy(event =>
      (
        event.callsiteFile,
        event.callsiteLine,
        event.callerFunction,
        event.calleeMethodFullName,
        event.calleeMethodName,
        event.decisionSource,
        event.predictedSanitizer,
        event.reason
      )
    )
    .values
    .map(_.head)
    .toList
    .sortBy(event =>
      (
        event.callsiteFile,
        event.callsiteLine,
        event.callerFunction,
        event.calleeMethodFullName,
        event.decisionSource,
        event.reason
      )
    )

  val decisionPayload = Obj(
    "stage" -> Str(stage),
    "config" -> Str(configName),
    "flow_mode" -> Str(selectedFlowMode),
    "modeled_policy" -> Str(policy.toString),
    "discovery_enabled" -> Bool(discoveryEnabled),
    "decision_count" -> Num(uniqueDecisionEvents.size),
    "decisions" -> Arr.from(uniqueDecisionEvents.map { event =>
      Obj(
        "stage" -> Str(stage),
        "config" -> Str(configName),
        "flow_mode" -> Str(selectedFlowMode),
        "callsite_file" -> Str(event.callsiteFile),
        "callsite_line" -> Num(event.callsiteLine),
        "caller_function" -> Str(event.callerFunction),
        "callee_method_full_name" -> Str(event.calleeMethodFullName),
        "callee_method_name" -> Str(event.calleeMethodName),
        "decision_source" -> Str(event.decisionSource),
        "predicted_sanitizer" -> Str(
          event.predictedSanitizer match {
            case Some(true)  => "true"
            case Some(false) => "false"
            case None        => "none"
          }
        ),
        "reason" -> Str(event.reason)
      )
    })
  )

  val outPath = Paths.get(outputPath)
  Option(outPath.getParent).foreach(Files.createDirectories(_))
  Files.writeString(outPath, write(payload, indent = 2, sortKeys = true))
  Option(decisionOutputPath).map(_.trim).filter(_.nonEmpty).foreach { path =>
    val decisionsPath = Paths.get(path)
    Option(decisionsPath.getParent).foreach(Files.createDirectories(_))
    Files.writeString(decisionsPath, write(decisionPayload, indent = 2, sortKeys = true))
    println(s"Wrote ${uniqueDecisionEvents.size} sanitizer decision events to ${decisionsPath}")
  }

  println(s"Wrote ${findings.size} findings to ${outputPath}")
}
