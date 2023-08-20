import { REQUEST_EVENTS } from "../../common/events.ts";
import {
  generateChannelId,
  generatePassword,
  generateUsername,
} from "../../utils/generate.ts";

const { stringify } = JSON;
const { CREATE_CHANNEL } = REQUEST_EVENTS;

export function createChannel(socket: WebSocket) {
  const defaultChannelId = generateChannelId();
  const defaultChannelPassword = generatePassword();
  const defaultUsername = generateUsername();

  const channelIdInput = prompt(
    "Enter a channel ID (or press eneter for default):",
    defaultChannelId
  );
  const channelPasswordInput = prompt(
    "Enter a password (or press enter for default):",
    defaultChannelPassword
  );
  const usernameInput = prompt(
    "Enter a username (or press enter for default):",
    defaultUsername
  );

  const payload = {
    event: CREATE_CHANNEL,
    channelId: channelIdInput || defaultChannelId,
    channelPassword: channelPasswordInput || defaultChannelPassword,
    username: usernameInput || defaultUsername,
  };

  socket.send(stringify(payload));
}
