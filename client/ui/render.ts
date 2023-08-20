import {
  bold,
  cyan,
  gray,
  green,
  red,
} from "https://deno.land/std@0.198.0/fmt/colors.ts";
import {
  ChannelCreated,
  ErrorMessage,
  MessageDelivered,
  SystemMessage,
} from "../types.ts";

const MAX_HISTORY_LENGTH = 500;
const chatHistory: string[] = [];

/**
 * Display the chat history on the console.
 */
export function renderChatHistory() {
  console.clear();
  chatHistory.forEach((message) => console.log(message));
  console.log("\nType your messages or commands below:");
}

/**
 * Display channel creation data.
 */
export function renderChannelCreated(data: ChannelCreated) {
  const { channelId, channelPassword } = data;
  chatHistory.push(
    gray(`Channel created with ID: ${channelId} | Password: ${channelPassword}`)
  );
}

/**
 * Display delivered message.
 */
export function renderMessageDelivered(data: MessageDelivered) {
  const { message, username } = data;
  chatHistory.push(`${bold(username)}: ${message}`);
  manageHistorySize();
}

/**
 * Display system messages.
 */
export function renderSystemMessage(data: SystemMessage) {
  chatHistory.push(cyan(`[System]: ${data.message}`));
  manageHistorySize();
}

/**
 * Display error messages.
 */
export function renderErrorMessage(data: ErrorMessage) {
  chatHistory.push(red(`[Error]: ${data.message}`));
  manageHistorySize();
}

/**
 * Display available commands.
 */
export function renderHelpCommands() {
  const DIVIDER = "────────────────────────────────────────────────────────";
  console.log(DIVIDER);
  console.log("                 Available Commands                     ");
  console.log(DIVIDER);
  console.log(`${bold("/create")} - Create a new chat channel.`);
  console.log(`${bold("/join")}   - Join an existing chat channel.`);
  console.log(`${bold("/leave")}  - Leave the current chat channel.`);
  console.log(`${bold("/help")}   - Display this help message.`);
  console.log(DIVIDER);
}

/**
 * Display welcome message.
 */
export function renderWelcome() {
  chatHistory.splice(0, chatHistory.length);

  console.clear();
  const DIVIDER = "────────────────────────────────────────────────────────";
  console.log(DIVIDER);
  console.log("                     Welcome to Termino                     ");
  console.log(DIVIDER);
  console.log(green(`Connected to server.`));
  console.log(
    `Type ${bold("/create")} to create a channel or ${bold(
      "/join"
    )} to join one.`
  );
  console.log(`For a list of all commands, type ${bold("/help")}.`);
  console.log(DIVIDER);
}

/**
 * Ensure chat history doesn't exceed maximum length.
 */
function manageHistorySize() {
  if (chatHistory.length > MAX_HISTORY_LENGTH) {
    chatHistory.shift();
  }
}
