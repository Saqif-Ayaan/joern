// Run: joern --script run_sanitizer_test.sc --param inputPath=<path-to-sanitizer-test-dir>
// Or from repo root: joern --script tests/code/c/sanitizer-test/run_sanitizer_test.sc --param inputPath=./tests/code/c/sanitizer-test

@main def main(inputPath: String) = {
  import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext, ModeledSanitizerValidationPolicy}
  importCode(inputPath)

  // --- cosmetic_check: syntactic sanitizer support is currently disabled, so expected flow is 1.
  val vulnSource = cpg.method("vulnerable").parameter.name("len")
  val vulnSink   = cpg.method("vulnerable").call("memcpy").argument(3)
  val cosmeticFlows = vulnSink.reachableBy(vulnSource).size

  // --- method_sanitizer.c (safe clamp): expected 0 flows after sanitizer validation.
  val methodSource = cpg.method("with_method_sanitizer").call("clamp").argument(1)
  val methodSink   = cpg.method("with_method_sanitizer").call("memcpy").argument(3)
  val methodFlows  = methodSink.reachableBy(methodSource).size

  // --- method_sanitizer_vuln.c (unsafe clamp): expected >= 1 flow, because validator should reject sanitizer model.
  val methodVulnSource = cpg.method("with_method_sanitizer_vuln").call("clamp_vuln").argument(1)
  val methodVulnSink   = cpg.method("with_method_sanitizer_vuln").call("memcpy").argument(3)
  val methodVulnFlows  = methodVulnSink.reachableBy(methodVulnSource).size

  // --- method_sanitizer_if.c (safe if/else clamp): expected 0 flows.
  val methodIfSource = cpg.method("with_method_sanitizer_if").call("clamp_if").argument(1)
  val methodIfSink   = cpg.method("with_method_sanitizer_if").call("memcpy").argument(3)
  val methodIfFlows  = methodIfSink.reachableBy(methodIfSource).size

  // --- method_sanitizer_early_return.c (safe early-return clamp): expected 0 flows.
  val methodEarlySource = cpg.method("with_method_sanitizer_early").call("clamp_early").argument(1)
  val methodEarlySink   = cpg.method("with_method_sanitizer_early").call("memcpy").argument(3)
  val methodEarlyFlows  = methodEarlySink.reachableBy(methodEarlySource).size

  // --- method_sanitizer_if_vuln.c (unsafe if/else): expected >= 1 flow.
  val methodIfVulnSource = cpg.method("with_method_sanitizer_if_vuln").call("clamp_if_vuln").argument(1)
  val methodIfVulnSink   = cpg.method("with_method_sanitizer_if_vuln").call("memcpy").argument(3)
  val methodIfVulnFlows  = methodIfVulnSink.reachableBy(methodIfVulnSource).size

  // --- method_sanitizer_many_assign.c (safe assignment-based clamp): expected 0 flows.
  val methodManyAssignSource = cpg.method("with_method_sanitizer_many_assign").call("clamp_many").argument(1)
  val methodManyAssignSink   = cpg.method("with_method_sanitizer_many_assign").call("memcpy").argument(3)
  val methodManyAssignFlows  = methodManyAssignSink.reachableBy(methodManyAssignSource).size

  // --- method_sanitizer_many_assign_vuln.c (unsafe assignment-based clamp): expected >= 1 flow.
  val methodManyAssignVulnSource = cpg.method("with_method_sanitizer_many_assign_vuln").call("clamp_many_vuln").argument(1)
  val methodManyAssignVulnSink   = cpg.method("with_method_sanitizer_many_assign_vuln").call("memcpy").argument(3)
  val methodManyAssignVulnFlows  = methodManyAssignVulnSink.reachableBy(methodManyAssignVulnSource).size

  // --- method_sanitizer_join_safe.c (safe join-based clamp): expected 0 flows.
  val methodJoinSafeSource = cpg.method("with_method_sanitizer_join_safe").call("clamp_join_safe").argument(1)
  val methodJoinSafeSink   = cpg.method("with_method_sanitizer_join_safe").call("memcpy").argument(3)
  val methodJoinSafeFlows  = methodJoinSafeSink.reachableBy(methodJoinSafeSource).size

  // --- method_sanitizer_call_assign_vuln.c (unsafe call assignment): expected >= 1 flow.
  val methodCallAssignVulnSource = cpg.method("with_method_sanitizer_call_assign_vuln").call("clamp_call_assign_vuln").argument(1)
  val methodCallAssignVulnSink   = cpg.method("with_method_sanitizer_call_assign_vuln").call("memcpy").argument(3)
  val methodCallAssignVulnFlows  = methodCallAssignVulnSink.reachableBy(methodCallAssignVulnSource).size

  // --- method_sanitizer_return_call_vuln.c (unsafe return call): expected >= 1 flow.
  val methodReturnCallVulnSource = cpg.method("with_method_sanitizer_return_call_vuln").call("clamp_return_call_vuln").argument(1)
  val methodReturnCallVulnSink   = cpg.method("with_method_sanitizer_return_call_vuln").call("memcpy").argument(3)
  val methodReturnCallVulnFlows  = methodReturnCallVulnSink.reachableBy(methodReturnCallVulnSource).size

  // --- unmodeled sanitizer pair used to validate dynamic auto-discovery flow.
  val unmodeledSafeSource = cpg.method("with_method_sanitizer_unmodeled_safe").call("clamp_unmodeled_safe").argument(1).l
  val unmodeledSafeSink   = cpg.method("with_method_sanitizer_unmodeled_safe").call("memcpy").argument(3).l
  val unmodeledVulnSource = cpg.method("with_method_sanitizer_unmodeled_vuln").call("clamp_unmodeled_vuln").argument(1).l
  val unmodeledVulnSink   = cpg.method("with_method_sanitizer_unmodeled_vuln").call("memcpy").argument(3).l

  val baselineContext  = EngineContext()
  val discoveryContext = EngineContext(config = EngineConfig(enableClampSanitizerAutoDiscovery = true))
  val warnContext = EngineContext(
    config = EngineConfig(modeledSanitizerValidationPolicy = ModeledSanitizerValidationPolicy.WARN)
  )
  val trustContext = EngineContext(
    config = EngineConfig(modeledSanitizerValidationPolicy = ModeledSanitizerValidationPolicy.TRUST)
  )

  val unmodeledSafeBaselineFlows  = unmodeledSafeSink.reachableBy(unmodeledSafeSource)(using baselineContext).size
  val unmodeledSafeDiscoveryFlows = unmodeledSafeSink.reachableBy(unmodeledSafeSource)(using discoveryContext).size
  val unmodeledVulnBaselineFlows  = unmodeledVulnSink.reachableBy(unmodeledVulnSource)(using baselineContext).size
  val unmodeledVulnDiscoveryFlows = unmodeledVulnSink.reachableBy(unmodeledVulnSource)(using discoveryContext).size
  val modeledCallAssignWarnFlows = cpg.method("with_method_sanitizer_call_assign_vuln")
    .call("memcpy")
    .argument(3)
    .l
    .reachableBy(cpg.method("with_method_sanitizer_call_assign_vuln").call("clamp_call_assign_vuln").argument(1).l)(using warnContext)
    .size
  val modeledCallAssignTrustFlows = cpg.method("with_method_sanitizer_call_assign_vuln")
    .call("memcpy")
    .argument(3)
    .l
    .reachableBy(cpg.method("with_method_sanitizer_call_assign_vuln").call("clamp_call_assign_vuln").argument(1).l)(using trustContext)
    .size

  println("=== Sanitizer test results ===")
  println(s"cosmetic_check (vulnerable): flows from len to memcpy(3) = $cosmeticFlows  (syntactic sanitizer disabled -> expected 1)")
  println(s"method_sanitizer.c (with_method_sanitizer): flows from len to memcpy(3) = $methodFlows  (validated safe clamp -> expected 0)")
  println(s"method_sanitizer_vuln.c (with_method_sanitizer_vuln): flows from len to memcpy(3) = $methodVulnFlows  (invalid clamp implementation -> expected >= 1)")
  println(s"method_sanitizer_if.c (with_method_sanitizer_if): flows from len to memcpy(3) = $methodIfFlows  (validated safe if/else clamp -> expected 0)")
  println(s"method_sanitizer_early_return.c (with_method_sanitizer_early): flows from len to memcpy(3) = $methodEarlyFlows  (validated safe early-return clamp -> expected 0)")
  println(s"method_sanitizer_if_vuln.c (with_method_sanitizer_if_vuln): flows from len to memcpy(3) = $methodIfVulnFlows  (invalid if/else implementation -> expected >= 1)")
  println(s"method_sanitizer_many_assign.c (with_method_sanitizer_many_assign): flows from len to memcpy(3) = $methodManyAssignFlows  (validated assignment-based clamp -> expected 0)")
  println(s"method_sanitizer_many_assign_vuln.c (with_method_sanitizer_many_assign_vuln): flows from len to memcpy(3) = $methodManyAssignVulnFlows  (invalid assignment-based implementation -> expected >= 1)")
  println(s"method_sanitizer_join_safe.c (with_method_sanitizer_join_safe): flows from len to memcpy(3) = $methodJoinSafeFlows  (validated join-based clamp -> expected 0)")
  println(s"method_sanitizer_call_assign_vuln.c (with_method_sanitizer_call_assign_vuln): flows from len to memcpy(3) = $methodCallAssignVulnFlows  (assignment from call is unsafe -> expected >= 1)")
  println(s"method_sanitizer_return_call_vuln.c (with_method_sanitizer_return_call_vuln): flows from len to memcpy(3) = $methodReturnCallVulnFlows  (return call result is unsafe -> expected >= 1)")
  println(s"method_sanitizer_unmodeled_safe.c baseline: flows from len to memcpy(3) = $unmodeledSafeBaselineFlows  (feature flag off -> expected >= 1)")
  println(s"method_sanitizer_unmodeled_safe.c discovery: flows from len to memcpy(3) = $unmodeledSafeDiscoveryFlows  (feature flag on -> expected 0)")
  println(s"method_sanitizer_unmodeled_vuln.c baseline: flows from len to memcpy(3) = $unmodeledVulnBaselineFlows  (feature flag off -> expected >= 1)")
  println(s"method_sanitizer_unmodeled_vuln.c discovery: flows from len to memcpy(3) = $unmodeledVulnDiscoveryFlows  (feature flag on -> expected >= 1)")
  println(s"method_sanitizer_call_assign_vuln.c warn policy: flows from len to memcpy(3) = $modeledCallAssignWarnFlows  (warn keeps modeled sanitizer -> expected 0)")
  println(s"method_sanitizer_call_assign_vuln.c trust policy: flows from len to memcpy(3) = $modeledCallAssignTrustFlows  (trust skips modeled sanitizer validation -> expected 0)")
  println("")
  if (cosmeticFlows == 1) {
    println("PASS cosmetic_check: flow detected as expected without syntactic sanitizer support.")
  } else {
    println("FAIL cosmetic_check: unexpected flow count; expected 1 with current engine behavior.")
  }
  if (methodFlows == 0) {
    println("PASS method_sanitizer: no tainted flow to sink (clamp recognized as sanitizer).")
  } else {
    println("FAIL method_sanitizer: flow(s) found; clamp should be in Semantics.")
  }
  if (methodVulnFlows >= 1) {
    println("PASS method_sanitizer_vuln: tainted flow detected (unsafe clamp not trusted as sanitizer).")
  } else {
    println("FAIL method_sanitizer_vuln: no flow found; unsafe clamp should not be trusted.")
  }
  if (methodIfFlows == 0) {
    println("PASS method_sanitizer_if: no tainted flow to sink (if/else clamp validated).")
  } else {
    println("FAIL method_sanitizer_if: flow(s) found; safe if/else clamp should be trusted.")
  }
  if (methodEarlyFlows == 0) {
    println("PASS method_sanitizer_early_return: no tainted flow to sink (early-return clamp validated).")
  } else {
    println("FAIL method_sanitizer_early_return: flow(s) found; safe early-return clamp should be trusted.")
  }
  if (methodIfVulnFlows >= 1) {
    println("PASS method_sanitizer_if_vuln: tainted flow detected (unsafe if/else sanitizer not trusted).")
  } else {
    println("FAIL method_sanitizer_if_vuln: no flow found; unsafe if/else sanitizer should not be trusted.")
  }
  if (methodManyAssignFlows == 0) {
    println("PASS method_sanitizer_many_assign: no tainted flow to sink (assignment-based clamp validated).")
  } else {
    println("FAIL method_sanitizer_many_assign: flow(s) found; safe assignment-based clamp should be trusted.")
  }
  if (methodManyAssignVulnFlows >= 1) {
    println("PASS method_sanitizer_many_assign_vuln: tainted flow detected (unsafe assignment-based sanitizer not trusted).")
  } else {
    println("FAIL method_sanitizer_many_assign_vuln: no flow found; unsafe assignment-based sanitizer should not be trusted.")
  }
  if (methodJoinSafeFlows == 0) {
    println("PASS method_sanitizer_join_safe: no tainted flow to sink (join-based clamp validated).")
  } else {
    println("FAIL method_sanitizer_join_safe: flow(s) found; join-based safe clamp should be trusted.")
  }
  if (methodCallAssignVulnFlows >= 1) {
    println("PASS method_sanitizer_call_assign_vuln: tainted flow detected (call assignment sanitizer not trusted).")
  } else {
    println("FAIL method_sanitizer_call_assign_vuln: no flow found; call-assignment sanitizer should not be trusted.")
  }
  if (methodReturnCallVulnFlows >= 1) {
    println("PASS method_sanitizer_return_call_vuln: tainted flow detected (return-call sanitizer not trusted).")
  } else {
    println("FAIL method_sanitizer_return_call_vuln: no flow found; return-call sanitizer should not be trusted.")
  }
  if (unmodeledSafeBaselineFlows >= 1) {
    println("PASS method_sanitizer_unmodeled_safe baseline: no pre-model means tainted flow is still present.")
  } else {
    println("FAIL method_sanitizer_unmodeled_safe baseline: expected flow without auto-discovery.")
  }
  if (unmodeledSafeDiscoveryFlows == 0) {
    println("PASS method_sanitizer_unmodeled_safe discovery: auto-discovery recognized clamp sanitizer.")
  } else {
    println("FAIL method_sanitizer_unmodeled_safe discovery: expected sanitizer discovery to remove flow.")
  }
  if (unmodeledVulnBaselineFlows >= 1) {
    println("PASS method_sanitizer_unmodeled_vuln baseline: unsafe unmodeled method keeps taint flow.")
  } else {
    println("FAIL method_sanitizer_unmodeled_vuln baseline: expected taint flow for unsafe method.")
  }
  if (unmodeledVulnDiscoveryFlows >= 1) {
    println("PASS method_sanitizer_unmodeled_vuln discovery: auto-discovery rejected unsafe implementation.")
  } else {
    println("FAIL method_sanitizer_unmodeled_vuln discovery: unsafe method should not be auto-discovered.")
  }
  if (modeledCallAssignWarnFlows == 0) {
    println("PASS method_sanitizer_call_assign_vuln warn policy: modeled sanitizer remains trusted.")
  } else {
    println("FAIL method_sanitizer_call_assign_vuln warn policy: expected modeled sanitizer to remain trusted.")
  }
  if (modeledCallAssignTrustFlows == 0) {
    println("PASS method_sanitizer_call_assign_vuln trust policy: modeled sanitizer trusted without validator gate.")
  } else {
    println("FAIL method_sanitizer_call_assign_vuln trust policy: expected modeled sanitizer trust.")
  }
}
