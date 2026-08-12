import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRelay } from "../../server/relay.ts";

/**
 * Scaffolding shared by the tests that need a live relay and somewhere on
 * disk to put an identity or a trust store. Nothing here knows anything about
 * termino's behaviour — it only sets up and tears down.
 *
 * It lives outside the mirrored directories on purpose: the rest of `test/`
 * matches `src/` and `shared/` file for file, and this matches neither.
 */

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface TestRelay {
  server: ReturnType<typeof startRelay>;
  /** The ephemeral port it bound, for a test that needs to sit in front of it. */
  port: number;
  /** What a session connects to. */
  url: string;
}

/**
 * Starts a relay on an ephemeral port, so a suite run never collides with a
 * relay somebody left running on 8787. Stop it with `server.stop(true)`.
 */
export function startTestRelay(): TestRelay {
  const server = startRelay({ port: 0 });

  // Bun types `Server.port` as optional; on a listening server it never is,
  // and a URL built from `undefined` fails much further downstream.
  const port = server.port;
  if (port === undefined) throw new Error("the test relay is not listening");

  return { server, port, url: `ws://localhost:${port}/` };
}

const created: string[] = [];

/**
 * A temporary directory, remembered for `removeTempDirs()`. Every test that
 * writes an identity key or a trust store goes through here rather than
 * touching the real `~/.termino`.
 */
export function tempDir(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), `termino-${prefix}-`));
  created.push(path);
  return path;
}

/** Deletes every directory `tempDir` has handed out. Call from `afterEach`. */
export function removeTempDirs(): void {
  for (const path of created) rmSync(path, { recursive: true, force: true });
  created.length = 0;
}
