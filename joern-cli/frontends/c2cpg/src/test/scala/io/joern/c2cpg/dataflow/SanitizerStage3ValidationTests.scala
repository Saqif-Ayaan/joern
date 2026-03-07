package io.joern.c2cpg.dataflow

import io.joern.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.joern.dataflowengineoss.queryengine.{
  ClampSanitizerDiscovery,
  EngineConfig,
  EngineContext,
  ModeledSanitizerValidationPolicy,
  QueryEngineStatistic,
  QueryEngineStatistics
}
import io.joern.dataflowengineoss.queryengine.BufferOverflowSanitizerValidator
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

import java.nio.charset.StandardCharsets
import java.nio.file.Files

class SanitizerStage3ValidationTests extends DataFlowCodeToCpgSuite {

  "stage-3-only sanitizer validation" should {
    val cpg = code("""
        |#define MAX 1024
        |
        |extern void* malloc(unsigned long);
        |extern void memcpy(void*, const void*, unsigned long);
        |extern void free(void*);
        |
        |typedef unsigned long size_t;
        |
        |size_t plus_one(size_t x) {
        |  return x + 1;
        |}
        |
        |size_t identity(size_t x) {
        |  return x;
        |}
        |
        |size_t clamp_join_safe(size_t n, int flag) {
        |  if (flag) {
        |    n = MAX;
        |  } else {
        |    n = 900;
        |  }
        |  return n;
        |}
        |
        |size_t clamp_call_assign_vuln(size_t n) {
        |  if (n > MAX) {
        |    n = plus_one(n);
        |  }
        |  return n;
        |}
        |
        |size_t clamp_return_call_vuln(size_t n) {
        |  return identity(n);
        |}
        |
        |size_t clamp_unmodeled_safe(size_t n) {
        |  if (n > MAX) {
        |    n = MAX;
        |  }
        |  return n;
        |}
        |
        |size_t clamp_unmodeled_vuln(size_t n) {
        |  if (n > MAX) {
        |    n = n + 1;
        |  }
        |  return n;
        |}
        |
        |char *clamp_ptr_passthrough(char *p) {
        |  return p;
        |}
        |
        |void with_method_sanitizer_join_safe(size_t len, char *src) {
        |  size_t sanitized_len = clamp_join_safe(len, 1);
        |  char *dst = (char *)malloc(sanitized_len + 1);
        |  if (!dst) return;
        |  memcpy(dst, src, sanitized_len);
        |  dst[sanitized_len] = '\\0';
        |  free(dst);
        |}
        |
        |void with_method_sanitizer_call_assign_vuln(size_t len, char *src) {
        |  size_t sanitized_len = clamp_call_assign_vuln(len);
        |  char *dst = (char *)malloc(sanitized_len + 1);
        |  if (!dst) return;
        |  memcpy(dst, src, sanitized_len);
        |  dst[sanitized_len] = '\\0';
        |  free(dst);
        |}
        |
        |void with_method_sanitizer_return_call_vuln(size_t len, char *src) {
        |  size_t sanitized_len = clamp_return_call_vuln(len);
        |  char *dst = (char *)malloc(sanitized_len + 1);
        |  if (!dst) return;
        |  memcpy(dst, src, sanitized_len);
        |  dst[sanitized_len] = '\\0';
        |  free(dst);
        |}
        |
        |void with_method_sanitizer_unmodeled_safe(size_t len, char *src) {
        |  size_t sanitized_len = clamp_unmodeled_safe(len);
        |  char *dst = (char *)malloc(sanitized_len + 1);
        |  if (!dst) return;
        |  memcpy(dst, src, sanitized_len);
        |  dst[sanitized_len] = '\\0';
        |  free(dst);
        |}
        |
        |void with_method_sanitizer_unmodeled_vuln(size_t len, char *src) {
        |  size_t sanitized_len = clamp_unmodeled_vuln(len);
        |  char *dst = (char *)malloc(sanitized_len + 1);
        |  if (!dst) return;
        |  memcpy(dst, src, sanitized_len);
        |  dst[sanitized_len] = '\\0';
        |  free(dst);
        |}
        |
        |void with_method_sanitizer_unmodeled_pointer(char *src, char *dst, size_t len) {
        |  char *sanitized_src = clamp_ptr_passthrough(src);
        |  memcpy(dst, sanitized_src, len);
        |}
        |""".stripMargin)

    "accept join-based safe clamp sanitizer" in {
      val validatorMethod = cpg.method.name("clamp_join_safe").head
      BufferOverflowSanitizerValidator.isValidatedSanitizer(validatorMethod).shouldBe(true)

      val source = cpg.call.name("clamp_join_safe").where(_.method.name("with_method_sanitizer_join_safe")).argument(1)
      val sink   = cpg.call.name("memcpy").where(_.method.name("with_method_sanitizer_join_safe")).argument(3)
      sink.reachableBy(source).size.shouldBe(0)
    }

    "reject sanitizer lookalike that assigns from a call" in {
      val validatorMethod = cpg.method.name("clamp_call_assign_vuln").head
      BufferOverflowSanitizerValidator.isValidatedSanitizer(validatorMethod).shouldBe(false)

      val source =
        cpg.call.name("clamp_call_assign_vuln").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(1)
      val sink =
        cpg.call.name("memcpy").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(3)
      sink.reachableBy(source).size.should(be >= 1)
    }

    "keep modeled sanitizer semantics on validator failure in WARN mode" in {
      val source =
        cpg.call.name("clamp_call_assign_vuln").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(1)
      val sink =
        cpg.call.name("memcpy").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(3)
      val warnContext = EngineContext(
        config = EngineConfig(modeledSanitizerValidationPolicy = ModeledSanitizerValidationPolicy.WARN)
      )

      sink.reachableBy(source)(using warnContext).size.shouldBe(0)
    }

    "trust modeled sanitizer semantics without validator gating in TRUST mode" in {
      val source =
        cpg.call.name("clamp_call_assign_vuln").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(1)
      val sink =
        cpg.call.name("memcpy").where(_.method.name("with_method_sanitizer_call_assign_vuln")).argument(3)
      val trustContext = EngineContext(
        config = EngineConfig(modeledSanitizerValidationPolicy = ModeledSanitizerValidationPolicy.TRUST)
      )

      sink.reachableBy(source)(using trustContext).size.shouldBe(0)
    }

    "reject sanitizer lookalike that returns a call result" in {
      val validatorMethod = cpg.method.name("clamp_return_call_vuln").head
      BufferOverflowSanitizerValidator.isValidatedSanitizer(validatorMethod).shouldBe(false)

      val source =
        cpg.call.name("clamp_return_call_vuln").where(_.method.name("with_method_sanitizer_return_call_vuln")).argument(1)
      val sink =
        cpg.call.name("memcpy").where(_.method.name("with_method_sanitizer_return_call_vuln")).argument(3)
      sink.reachableBy(source).size.should(be >= 1)
    }

    "not auto-discover unmodeled clamp sanitizer when feature flag is off" in {
      val source = cpg.call
        .name("clamp_unmodeled_safe")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(1)
      val sink = cpg.call
        .name("memcpy")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(3)

      sink.reachableBy(source).size.should(be >= 1)
    }

    "auto-discover unmodeled clamp sanitizer when feature flag is on" in {
      val source = cpg.call
        .name("clamp_unmodeled_safe")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(1)
      val sink = cpg.call
        .name("memcpy")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(3)
      val discoveryContext = EngineContext(config = EngineConfig(enableClampSanitizerAutoDiscovery = true))

      sink.reachableBy(source)(using discoveryContext).size.shouldBe(0)
    }

    "not auto-discover unsafe unmodeled method when feature flag is on" in {
      val source = cpg.call
        .name("clamp_unmodeled_vuln")
        .where(_.method.name("with_method_sanitizer_unmodeled_vuln"))
        .argument(1)
      val sink = cpg.call
        .name("memcpy")
        .where(_.method.name("with_method_sanitizer_unmodeled_vuln"))
        .argument(3)
      val discoveryContext = EngineContext(config = EngineConfig(enableClampSanitizerAutoDiscovery = true))

      sink.reachableBy(source)(using discoveryContext).size.should(be >= 1)
    }

    "exclude non-numeric return methods from auto-discovery candidates" in {
      val source = cpg.call
        .name("clamp_ptr_passthrough")
        .where(_.method.name("with_method_sanitizer_unmodeled_pointer"))
        .argument(1)
      val sink = cpg.call
        .name("memcpy")
        .where(_.method.name("with_method_sanitizer_unmodeled_pointer"))
        .argument(2)
      val discoveryContext = EngineContext(config = EngineConfig(enableClampSanitizerAutoDiscovery = true))

      sink.reachableBy(source)(using discoveryContext).size.should(be >= 1)
    }

    "persist discovery decisions and reload sidecar cache" in {
      val source = cpg.call
        .name("clamp_unmodeled_safe")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(1)
      val sink = cpg.call
        .name("memcpy")
        .where(_.method.name("with_method_sanitizer_unmodeled_safe"))
        .argument(3)

      val cachePath = Files.createTempFile("clamp-sanitizer-discovery-", ".json")
      Files.deleteIfExists(cachePath)

      val discoveryContext = EngineContext(
        config = EngineConfig(
          enableClampSanitizerAutoDiscovery = true,
          clampSanitizerDecisionCachePath = Some(cachePath.toAbsolutePath.toString)
        )
      )

      QueryEngineStatistics.reset()
      ClampSanitizerDiscovery.resetForTests()
      BufferOverflowSanitizerValidator.clearCacheForTests()

      sink.reachableBy(source)(using discoveryContext).size.shouldBe(0)
      Files.exists(cachePath).shouldBe(true)
      val sidecarContents = Files.readString(cachePath, StandardCharsets.UTF_8)
      sidecarContents.contains("clamp_unmodeled_safe").shouldBe(true)

      QueryEngineStatistics.reset()
      ClampSanitizerDiscovery.resetForTests()
      BufferOverflowSanitizerValidator.clearCacheForTests()

      val cachedMethod = cpg.method.name("clamp_unmodeled_safe").head
      ClampSanitizerDiscovery
        .semanticForUnmodeledMethod(cachedMethod, discoveryContext.config)
        .nonEmpty
        .shouldBe(true)
      val cacheHits = QueryEngineStatistics.results().getOrElse(QueryEngineStatistic.CLAMP_DISCOVERY_CACHE_HITS, 0L)
      cacheHits.should(be >= 1L)
      sink.reachableBy(source)(using discoveryContext).size.shouldBe(0)
    }

    "invalidate stale sidecar decisions when method fingerprint changes" in {
      val cachePath = Files.createTempFile("clamp-sanitizer-fingerprint-", ".json")
      Files.deleteIfExists(cachePath)

      val discoveryContext = EngineContext(
        config = EngineConfig(
          enableClampSanitizerAutoDiscovery = true,
          clampSanitizerDecisionCachePath = Some(cachePath.toAbsolutePath.toString)
        )
      )

      val cpgV1 = code(
        """
          |#define MAX 1024
          |extern void memcpy(void*, const void*, unsigned long);
          |extern void* malloc(unsigned long);
          |extern void free(void*);
          |typedef unsigned long size_t;
          |
          |size_t clamp_fingerprint(size_t n) {
          |  if (n > MAX) n = MAX;
          |  return n;
          |}
          |
          |void with_fingerprint(size_t len, char *src) {
          |  size_t sanitized_len = clamp_fingerprint(len);
          |  char *dst = (char *)malloc(sanitized_len + 1);
          |  if (!dst) return;
          |  memcpy(dst, src, sanitized_len);
          |  dst[sanitized_len] = '\\0';
          |  free(dst);
          |}
          |""".stripMargin,
        "sidecar_fingerprint.c"
      )
      val sourceV1 = cpgV1.call.name("clamp_fingerprint").where(_.method.name("with_fingerprint")).argument(1)
      val sinkV1   = cpgV1.call.name("memcpy").where(_.method.name("with_fingerprint")).argument(3)

      QueryEngineStatistics.reset()
      ClampSanitizerDiscovery.resetForTests()
      BufferOverflowSanitizerValidator.clearCacheForTests()
      sinkV1.reachableBy(sourceV1)(using discoveryContext).size.shouldBe(0)

      QueryEngineStatistics.reset()
      ClampSanitizerDiscovery.resetForTests()
      BufferOverflowSanitizerValidator.clearCacheForTests()

      val cpgV2 = code(
        """
          |#define MAX 1024
          |extern void memcpy(void*, const void*, unsigned long);
          |extern void* malloc(unsigned long);
          |extern void free(void*);
          |typedef unsigned long size_t;
          |
          |size_t passthrough(size_t x) {
          |  return x;
          |}
          |
          |size_t clamp_fingerprint(size_t n) {
          |  return passthrough(n);
          |}
          |
          |void with_fingerprint(size_t len, char *src) {
          |  size_t sanitized_len = clamp_fingerprint(len);
          |  char *dst = (char *)malloc(sanitized_len + 1);
          |  if (!dst) return;
          |  memcpy(dst, src, sanitized_len);
          |  dst[sanitized_len] = '\\0';
          |  free(dst);
          |}
          |""".stripMargin,
        "sidecar_fingerprint.c"
      )
      val sourceV2 = cpgV2.call.name("clamp_fingerprint").where(_.method.name("with_fingerprint")).argument(1)
      val sinkV2   = cpgV2.call.name("memcpy").where(_.method.name("with_fingerprint")).argument(3)

      sinkV2.reachableBy(sourceV2)(using discoveryContext).size.should(be >= 1)
    }
  }

}
