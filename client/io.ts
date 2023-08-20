import { readLines } from "https://deno.land/std@0.198.0/io/read_lines.ts";
import { createChannel } from "./handlers/create_channel.ts";
import { joinChannel } from "./handlers/join_channel.ts";
import { leaveChannel } from "./handlers/leave_channel.ts";
import { sendMessage } from "./handlers/send_message.ts";
import { renderHelpCommands } from "./ui/render.ts";

export async function handleUserInput(socket: WebSocket) {
  for await (const line of readLines(Deno.stdin)) {
    const input = line.trim();

    if (!input) continue;

    if (input.startsWith("/")) {
      switch (input) {
        case "/create":
          createChannel(socket);
          break;

        case "/join":
          joinChannel(socket);
          break;

        case "/leave": {
          leaveChannel(socket);
          break;
        }
        case "/help":
          renderHelpCommands();
          break;
        case "/exit":
          socket.close();
          Deno.exit(0);
          break;
        default:
          console.log(`Unknown command: ${input}`);
      }
    } else {
      sendMessage(socket, input);
    }
  }
}
