import { RouterContext } from "https://deno.land/x/oak@v12.6.0/mod.ts";
import { handleClose, handleMessage } from "./socket_events.ts";
import { CustomSocket } from "./managers/channel_manager.ts";

type Context = RouterContext<
  "/start",
  Record<string | number, string | undefined>,
  Record<string, unknown>
>;

export async function handler(ctx: Context) {
  try {
    const socket = (await ctx.upgrade()) as CustomSocket;
    socket.onmessage = handleMessage(socket);
    socket.onclose = handleClose(socket);
  } catch (error) {
    console.error(`Failed to set up WebSocket for client: ${error}`);
  }
}
