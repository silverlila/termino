import { RESPONSE_EVENTS } from "../../common/events.ts";
import {
  CustomSocket,
  broadcast,
  destroyChannel,
  getClientsFromChannel,
  removeClientFromChannel,
} from "../managers/channel_manager.ts";

const { stringify } = JSON;

export function leaveChannelHandler(socket: CustomSocket) {
  const { channelKey } = socket;
  const clients = getClientsFromChannel(channelKey);

  if (clients) {
    const index = clients.indexOf(socket);
    if (index > -1) {
      removeClientFromChannel(socket);

      if (clients.length === 0) {
        destroyChannel(channelKey);
        return;
      }

      const payload = stringify({
        event: RESPONSE_EVENTS.USER_LEFT,
        message: `User ${socket.username} has left the chat.`,
      });

      broadcast(channelKey, payload);
    }
  }
}
