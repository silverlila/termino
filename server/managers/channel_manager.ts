export interface CustomSocket extends WebSocket {
  channelKey: string;
  username: string;
  publicKey: string;
}

// Map to keep track of connected clients per channel.
const channelManager = new Map<string, CustomSocket[]>();

/**
 * Adds a client to a specific channel.
 * @param key - The channel identifier.
 * @param socket - The client's socket to add.
 */
export function addClientToChannel(key: string, socket: CustomSocket): void {
  const clients = channelManager.get(key) || [];
  clients.push(socket);
  channelManager.set(key, clients);
}

/**
 * Removes a client from its channel.
 * @param socket - The client's socket to remove.
 * @returns - The key of the channel from which the client was removed, or null if not found.
 */
export function removeClientFromChannel(socket: CustomSocket): string | null {
  for (const [key, clients] of channelManager.entries()) {
    const index = clients.indexOf(socket);
    if (index !== -1) {
      clients.splice(index, 1);
      socket.close();

      if (clients.length === 0) {
        channelManager.delete(key);
      }
      return key;
    }
  }
  return null;
}

/**
 * Retrieves all clients from a specific channel.
 * @param key - The channel identifier.
 * @returns - An array of clients or undefined if the channel doesn't exist.
 */
export function getClientsFromChannel(key: string): CustomSocket[] {
  return channelManager.get(key) || [];
}

/**
 * Removes all clients from a specific channel and destroys the channel.
 * @param key - The channel identifier.
 */
export function destroyChannel(key: string): void {
  channelManager.delete(key);
}

/**
 * Sends a message to all clients in a specific channel.
 * @param key - The channel identifier.
 * @param message - The message to send.
 */
export function broadcast(key: string, message: string): void {
  const clients = getClientsFromChannel(key);
  if (!clients) return;

  for (const socket of clients) {
    try {
      socket.send(message);
    } catch (error) {
      console.error(`Failed to send message to socket: ${error}`);
      removeClientFromChannel(socket);
    }
  }
}
