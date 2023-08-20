import { EVENTS, RESPONSE_EVENTS } from "../../common/events.ts";
import { CustomSocket, broadcast } from "../managers/channel_manager.ts";
import { canSend } from "../managers/rate_limiter.ts";
import { MessagePayload } from "../types.ts";

const { stringify } = JSON;
const { MESSAGE_DELIVERED } = RESPONSE_EVENTS;

export function sendMessageHandler(data: MessagePayload, socket: CustomSocket) {
  if (!canSend(socket.username)) {
    const message = "You're sending messages too frequently. Please wait.";
    socket.send(stringify({ type: EVENTS.ERROR, message }));
    return;
  }

  const pyaload = {
    event: MESSAGE_DELIVERED,
    username: socket.username,
    message: data.message,
  };

  broadcast(socket.channelKey, stringify(pyaload));
}
