import { handleUserInput } from "./io.ts";
import { RESPONSE_EVENTS } from "../common/events.ts";
import {
  renderChannelCreated,
  renderChatHistory,
  renderErrorMessage,
  renderMessageDelivered,
  renderSystemMessage,
  renderWelcome,
} from "./ui/render.ts";

export function handleOpen(socket: WebSocket) {
  return async () => {
    renderWelcome();
    await handleUserInput(socket);
  };
}

export function handleMessage() {
  return (event: MessageEvent) => {
    const data = JSON.parse(event.data);

    switch (data.event) {
      case RESPONSE_EVENTS.CHANNEL_CREATED:
        renderChannelCreated(data);
        break;

      case RESPONSE_EVENTS.MESSAGE_DELIVERED:
        renderMessageDelivered(data);
        break;

      case RESPONSE_EVENTS.USER_JOINED:
      case RESPONSE_EVENTS.USER_LEFT:
        renderSystemMessage(data);
        break;

      case RESPONSE_EVENTS.ERROR:
        renderErrorMessage(data);
        break;
    }

    renderChatHistory();
  };
}

export function handleError() {
  return (error: Event | ErrorEvent) => {
    console.error("WebSocket Error:", error);
    Deno.exit(0);
  };
}

export function handleClose() {
  return () => {
    renderWelcome();
  };
}
