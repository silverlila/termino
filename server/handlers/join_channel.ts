import { EVENTS } from "../../common/events.ts";
import { generateHashKey } from "../../utils/generate.ts";
import { JoinChannelPayload } from "../types.ts";
import {
  CustomSocket,
  broadcast,
  getClientsFromChannel,
} from "../managers/channel_manager.ts";

const { stringify } = JSON;

export async function joinChannelHandler(
  data: JoinChannelPayload,
  socket: CustomSocket
) {
  const { channelId, channelPassword, username } = data;
  const channelKey = await generateHashKey(channelId, channelPassword);
  const clients = getClientsFromChannel(channelKey);

  if (clients.length === 0) {
    const payload = { event: EVENTS.ERROR, message: "Channel not found." };
    socket.send(stringify(payload));
    return;
  }

  socket.channelKey = channelKey;
  socket.username = username;

  clients.push(socket);

  const userHasJoinedPayload = stringify({
    event: EVENTS.USER_JOINED,
    message: `User ${username} just joined!`,
  });

  broadcast(channelKey, userHasJoinedPayload);
}
