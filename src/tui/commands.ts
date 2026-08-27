export const COMMANDS = [
  { usage: "/help", summary: "list these commands" },
  { usage: "/exit", summary: "leave the channel and close termino" },
] as const;

export type ComposerInput =
  | { kind: "message"; body: string }
  | { kind: "help" }
  | { kind: "exit" }
  | { kind: "unusable"; reason: string };

export function parseComposerInput(line: string): ComposerInput {
  const trimmed = line.trim();
  if (!trimmed.startsWith("/")) return { kind: "message", body: trimmed };

  const [name = ""] = trimmed.split(/\s+/);

  if (name === "/help") return { kind: "help" };
  if (name === "/exit") return { kind: "exit" };

  return { kind: "unusable", reason: `unknown command ${name} — /help lists them` };
}
