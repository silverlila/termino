import { REQUEST_EVENTS } from "../../common/events.ts";

const { stringify } = JSON;
const { SEND_MESSAGE } = REQUEST_EVENTS;

export function sendMessage(socket: WebSocket, message: string) {
  const payload = { event: SEND_MESSAGE, message };
  socket.send(stringify(payload));
}
