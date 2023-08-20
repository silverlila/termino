import {
  handleClose,
  handleError,
  handleMessage,
  handleOpen,
} from "./socket_events.ts";

export function startClient(endpoint = `ws://localhost:8080/start`) {
  const socket = new WebSocket(endpoint);
  socket.onopen = handleOpen(socket);
  socket.onmessage = handleMessage();
  socket.onerror = handleError();
  socket.onclose = handleClose();
}
