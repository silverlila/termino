import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
// The generators and the time bound live with the long run rather than here, so
// `bun run scripts/fuzz-long.ts --budget 3600` and the suite drive exactly the
// same targets through exactly the same code.
import {
  check,
  describeFinding,
  frameBytesTarget,
  frameTarget,
  fuzz,
  type FuzzReport,
  MAX_PARSE_MS,
  payloadTarget,
  type Target,
  TARGETS,
} from "../../../scripts/fuzz-long.ts";

const SUITE_BUDGET_MS = 1_500;

function expectNoFindings(report: FuzzReport): void {
  // The seed rides along inside the assertion so a failure names the run that
  // produced it — `--seed <n>` replays it exactly.
  expect([`seed ${report.seed}`, ...report.findings.map(describeFinding)]).toEqual([
    `seed ${report.seed}`,
  ]);
}

describe("fuzzing decodeFrame", () => {
  it(
    "throws only FrameError, for anything arriving as text or as bytes",
    () => {
      const report = fuzz({
        budgetMs: SUITE_BUDGET_MS,
        targets: [frameTarget, frameBytesTarget],
      });

      expectNoFindings(report);
      // Not a performance assertion: it fails a run whose generators produced
      // nothing, which would make the case above pass over an empty budget.
      expect(report.cases).toBeGreaterThan(100);
    },
    10_000,
  );
});

describe("fuzzing parsePayload", () => {
  it(
    "throws only PayloadError, for anything a message might decrypt to",
    () => {
      const report = fuzz({ budgetMs: SUITE_BUDGET_MS, targets: [payloadTarget] });

      expectNoFindings(report);
      expect(report.cases).toBeGreaterThan(100);
    },
    10_000,
  );
});

describe("the committed corpus", () => {
  const CORPUS_DIR = join(import.meta.dir, "..", "..", "corpus");
  const files = readdirSync(CORPUS_DIR)
    .filter((name) => name.endsWith(".txt"))
    .sort();

  it("is not empty, so replaying it cannot pass vacuously", () => {
    expect(files.length).toBeGreaterThanOrEqual(12);
  });

  it(
    "replays every input a run has found interesting, through every parser",
    () => {
      const findings = files
        .flatMap((name) => {
          const input = readFileSync(join(CORPUS_DIR, name), "utf8");
          return TARGETS.map((target) => check(target, input, name));
        })
        .filter((finding) => finding !== null);

      expect(findings.map(describeFinding)).toEqual([]);
    },
    20_000,
  );
});

describe("the fuzz harness itself", () => {
  it("reports a parser that throws an error it does not declare", () => {
    const undeclared: Target = {
      name: "throws TypeError",
      parse: () => {
        throw new TypeError("boom");
      },
      declaresError: () => false,
    };

    expect(check(undeclared, "anything", "a test")?.problem).toBe("threw TypeError: boom");
  });

  it("reports a parser that spends longer on one input than the bound allows", () => {
    const slow: Target = {
      name: "spins",
      parse: () => {
        const until = performance.now() + MAX_PARSE_MS * 2;
        while (performance.now() < until) {
          // Spinning rather than sleeping: a parser that hangs holds the thread.
        }
      },
      declaresError: () => false,
    };

    expect(check(slow, "anything", "a test")?.problem).toContain(`over the ${MAX_PARSE_MS} ms`);
  });
});
