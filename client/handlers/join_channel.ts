import { REQUEST_EVENTS } from "../../common/events.ts";
import { generateUsername } from "../../utils/generate.ts";

const { stringify } = JSON;
const { JOIN_CHANNEL } = REQUEST_EVENTS;

export function joinChannel(socket: WebSocket) {
  const channelId = prompt(`Please provider a channel ID:`);
  const channelPassword = prompt(`Please provider a channel password:`);

  if (!channelId || !channelPassword) {
    console.error("Please provider a channel ID and a channel password.");
    socket.close();
    Deno.exit();
  }

  const defaultUsername = generateUsername();
  const usernameInput = prompt(
    `Please provide a username (or press enter for default):`,
    defaultUsername
  );
  const username = usernameInput || defaultUsername;

  const payload = {
    event: JOIN_CHANNEL,
    channelId,
    channelPassword,
    username,
  };

  socket.send(stringify(payload));
}
