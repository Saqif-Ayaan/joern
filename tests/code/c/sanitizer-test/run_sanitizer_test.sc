// Run: joern --script run_sanitizer_test.sc --param inputPath=<path-to-sanitizer-test-dir>
// Or from repo root: joern --script tests/code/c/sanitizer-test/run_sanitizer_test.sc --param inputPath=./tests/code/c/sanitizer-test

@main def main(inputPath: String) = {
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

  println("=== Sanitizer test results ===")
  println(s"cosmetic_check (vulnerable): flows from len to memcpy(3) = $cosmeticFlows  (syntactic sanitizer disabled → expected 1)")
  println(s"method_sanitizer.c (with_method_sanitizer): flows from len to memcpy(3) = $methodFlows  (validated safe clamp → expected 0)")
  println(s"method_sanitizer_vuln.c (with_method_sanitizer_vuln): flows from len to memcpy(3) = $methodVulnFlows  (invalid clamp implementation → expected >= 1)")
  println(s"method_sanitizer_if.c (with_method_sanitizer_if): flows from len to memcpy(3) = $methodIfFlows  (validated safe if/else clamp → expected 0)")
  println(s"method_sanitizer_early_return.c (with_method_sanitizer_early): flows from len to memcpy(3) = $methodEarlyFlows  (validated safe early-return clamp → expected 0)")
  println(s"method_sanitizer_if_vuln.c (with_method_sanitizer_if_vuln): flows from len to memcpy(3) = $methodIfVulnFlows  (invalid if/else implementation → expected >= 1)")
  println(s"method_sanitizer_many_assign.c (with_method_sanitizer_many_assign): flows from len to memcpy(3) = $methodManyAssignFlows  (validated assignment-based clamp → expected 0)")
  println(s"method_sanitizer_many_assign_vuln.c (with_method_sanitizer_many_assign_vuln): flows from len to memcpy(3) = $methodManyAssignVulnFlows  (invalid assignment-based implementation → expected >= 1)")
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
}
