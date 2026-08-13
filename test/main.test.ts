import { afterEach, describe, expect, it } from "bun:test";
import { loadRenderer } from "../src/main.ts";

/**
 * The CLI, at the seams a test can reach. `runClient` and `main` are not among
 * them: they prompt on stdin, spend ~850 ms in argon2id, write to the real
 * `~/.termino`, and end in a renderer that hangs without a TTY.
 */

const originalDev = process.env.DEV;

afterEach(() => {
  if (originalDev === undefined) delete process.env.DEV;
  else process.env.DEV = originalDev;
});

describe("devtools", () => {
  it("clears DEV before importing the renderer", async () => {
    // `@opentui/react` reads this as it evaluates, and on `true` it connects
    // React devtools to a local WebSocket — which serialises the element tree
    // with its props. Nothing secret is a prop any more, and the flag is
    // cleared as well: one forgotten path should not be enough to leak a key.
    process.env.DEV = "true";

    await loadRenderer();

    expect(process.env.DEV).toBeUndefined();
  });
});
