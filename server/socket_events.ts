import { EVENTS, REQUEST_EVENTS } from "../common/events.ts";
import { createChannelHandler } from "./handlers/create_channel.ts";
import { joinChannelHandler } from "./handlers/join_channel.ts";
import { leaveChannelHandler } from "./handlers/leave_channel.ts";
import { sendMessageHandler } from "./handlers/send_message.ts";
import { CustomSocket } from "./managers/channel_manager.ts";

const { stringify } = JSON;

export function handleMessage(socket: CustomSocket) {
  return async (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);

      switch (data.event) {
        case REQUEST_EVENTS.CREATE_CHANNEL:
          await createChannelHandler(data, socket);
          break;

        case REQUEST_EVENTS.JOIN_CHANNEL:
          await joinChannelHandler(data, socket);
          break;

        case REQUEST_EVENTS.LEAVE_CHANNEL:
          leaveChannelHandler(socket);
          break;

        case REQUEST_EVENTS.SEND_MESSAGE:
          sendMessageHandler(data, socket);
          break;

        default: {
          const message = "Received an unknown event type.";
          const payload = stringify({ type: EVENTS.ERROR, message });
          socket.send(payload);
          break;
        }
      }
    } catch (error) {
      if (error instanceof SyntaxError) {
        console.error("Failed to parse incoming message:", event.data);
        const message = "Malformed message received.";
        const pyaload = stringify({ type: "error", message });
        socket.send(pyaload);
      } else {
        console.error("An unexpected error occurred:", error);
        const message =
          "An unexpected error occurred while processing your message.";
        const pyaload = stringify({ type: "error", message });
        socket.send(pyaload);
      }
    }
  };
}

export function handleClose(socket: CustomSocket) {
  return () => leaveChannelHandler(socket);
}
