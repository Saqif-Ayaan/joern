# Testing Joern on a File That Meets Criteria for the “Syntactic Sanitizer” Change

This folder contains C files and steps to test the **current** Joern behavior on a “cosmetic” syntactic check (no sanitizer method), and to contrast with a method-based sanitizer.

---

## 1. What These Files Represent

| File | Purpose |
|------|--------|
| **cosmetic_check.c** | **Syntactic sanitizer, not a method.** Has a bare conditional `if (len > MAX) log_msg(...)` but execution still reaches `memcpy(dst, src, len)` with tainted `len` and `src`. So the check is cosmetic. Current Joern does **not** treat this conditional as a sanitizer → the flow **should be reported** (source → sink). |
| **method_sanitizer.c** | **Method-based sanitizer.** Uses `clamp(len)`; if `clamp` were registered in Semantics as a sanitizer, taint would stop at that call. Used to contrast with the cosmetic case. |

---

## 2. Prerequisites

- **JDK 21** (or compatible)
- **sbt** (for building from source), **or** the Joern install script (pre-built)
- For C: **gcc** optional but useful for include discovery

---

## 3. Option A: Use Pre-Built Joern (Fastest)

### 3.1 Install Joern

```bash
cd /path/to/joern   # or any directory
wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x ./joern-install.sh
sudo ./joern-install.sh
```

### 3.2 Run Joern and Import the Test Directory

```bash
joern
```

In the Joern shell:

```scala
importCode("./tests/code/c/sanitizer-test")
```

Use the path that points to the folder containing `cosmetic_check.c` and `method_sanitizer.c`. From the **repo root** it is `./tests/code/c/sanitizer-test` (or the full path, e.g. `/Users/saqif/Desktop/UCSB/ucsb_classes/w26/cs293G/joern/tests/code/c/sanitizer-test`).

---

## 4. Option B: Build and Run from Source

### 4.1 Build a Runnable Distribution

From the **Joern repo root**:

```bash
cd /Users/saqif/Desktop/UCSB/ucsb_classes/w26/cs293G/joern
sbt joerncli/stage
```

### 4.2 Run the Staged Joern

The staged binary is usually under something like:

```bash
./joern-cli/target/universal/stage/bin/joern
```

Or from repo root, run the script that `sbt joerncli/stage` reports.

### 4.3 Import the Test Directory

In the Joern shell, from the **repo root** (so paths line up):

```scala
importCode("./tests/code/c/sanitizer-test")
```

Or use the absolute path to `sanitizer-test`.

---

## 5. Run a Source-to-Sink Dataflow Query (Cosmetic Check)

After `importCode(...)` completes, run a query that finds flows from a **source** (e.g. parameter) to a **sink** (e.g. `memcpy`). Because the current codebase does **not** treat the bare `if (len > MAX)` as a sanitizer, the flow should still be found.

In the Joern shell (imports are usually pre-configured; if not, add the ones from the dataflow README):

```scala
// Define source: parameters of the vulnerable function (tainted inputs)
def source = cpg.method("vulnerable").parameter

// Define sink: third argument of memcpy (size = len, tainted)
def sink = cpg.call("memcpy").argument(3)

// Backward dataflow: can any sink be reached by any source?
sink.reachableBy(source).p
```

- If you get **one or more paths** → the engine correctly does **not** treat the bare conditional as a sanitizer; the “cosmetic check” does not prune the flow.
- You can also inspect:

```scala
sink.reachableBy(source).size
cpg.method("vulnerable").l
cpg.call("memcpy").argument(3).l
```

---

## 6. Optional: Run as a Script

You can put the same logic in a script and run it (e.g. with the staged Joern that accepts a script). Example script content (e.g. `run_sanitizer_test.sc`):

```scala
@main def main(inputPath: String) = {
  importCode(inputPath)
  val src   = cpg.method("vulnerable").parameter
  val snk   = cpg.call("memcpy").argument(3)
  val paths = snk.reachableBy(src).l
  println(s"Paths from source to sink: ${paths.size}")
  paths.foreach(p => println(p.map(_.code).mkString(" -> ")))
}
```

Run it (syntax depends on your Joern install; often something like):

```bash
joern --script run_sanitizer_test.sc --params inputPath=./tests/code/c/sanitizer-test
```

Exact CLI may vary; check `joern --help` or the docs.

---

## 7. What This Demonstrates for Your Change

- **Current behavior:** Only **method-call** sanitizers (declared in Semantics) prune taint. A bare conditional like `if (len > MAX) log_msg(...)` is **not** a sanitizer, so the flow from `len`/`src` to `memcpy` is still reported.
- **Your improvement:** If you later add **syntactic** sanitizer detection (e.g. “conditional involving tainted variable”), you would **only** prune after an **effectiveness** check: the “bad” branch must exit/return or otherwise not reach the sink with tainted data. This test file is the kind of case that would remain **unsanitized** under that policy (cosmetic check → flow still reported).

---

## 8. After the syntactic-sanitizer change

The codebase was modified to **identify syntactic sanitizers** (e.g. condition of an `if` involving the tainted variable) and **only prune when the check is effective** (the "bad" branch does not CFG-reach the sink).

- **cosmetic_check.c**: The `if (len > MAX) log_msg(...)` is a syntactic check but the bad branch (whenTrue) still reaches `memcpy`, so the sanitizer is **not effective**. The engine does **not** prune; the flow is still reported (vulnerability found). Correct.
- **method_sanitizer.c**: Uses `clamp(len)`; `clamp` is in DefaultSemantics as a sanitizer (no flow param→return), so taint stops at the call. No flow to sink. Correct.

Run the same script after building; both tests should pass (correct outcomes, no false positives or false negatives).

## 9. Troubleshooting

- **`importCode` fails or no CPG:** Ensure the path is to the **directory** containing the `.c` files (e.g. `sanitizer-test`), not to a single file. Use absolute path if needed.
- **No methods/calls found:** Run `cpg.method.name.l` and `cpg.call.name.l` to see what was imported; adjust `vulnerable` and `memcpy` if names differ (e.g. C++ mangling).
- **C parse errors:** The test files use minimal `extern` declarations. If your Joern/C frontend needs includes, add `#include <stdlib.h>` and `#include <string.h>` and adjust.
