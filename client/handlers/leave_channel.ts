import { REQUEST_EVENTS } from "../../common/events.ts";

const { LEAVE_CHANNEL } = REQUEST_EVENTS;

export function leaveChannel(socket: WebSocket) {
  const payload = JSON.stringify({ event: LEAVE_CHANNEL });
  socket.send(payload);
}
