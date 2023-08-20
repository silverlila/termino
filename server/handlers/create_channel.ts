import { RESPONSE_EVENTS } from "../../common/events.ts";
import { generateHashKey } from "../../utils/generate.ts";
import { CreateChannelPayload } from "../types.ts";
import { addClientToChannel } from "../managers/channel_manager.ts";
import type { CustomSocket } from "../managers/channel_manager.ts";

const { stringify } = JSON;
const { CHANNEL_CREATED } = RESPONSE_EVENTS;

export async function createChannelHandler(
  data: CreateChannelPayload,
  socket: CustomSocket
) {
  const { channelId, channelPassword, username } = data;
  const channelKey = await generateHashKey(channelId, channelPassword);

  socket.channelKey = channelKey;
  socket.username = username;

  addClientToChannel(channelKey, socket);

  const payload = {
    event: CHANNEL_CREATED,
    channelId,
    channelPassword,
  };

  socket.send(stringify(payload));
}
