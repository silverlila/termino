const messageTimestamps: Map<string, Date[]> = new Map();
const MESSAGE_LIMIT_DURATION = 10000;
const MESSAGE_LIMIT_COUNT = 5;

export function canSend(username: string): boolean {
  const now = new Date();
  const userTimestamps = messageTimestamps.get(username) || [];

  // Remove timestamps that are older than our limit duration.
  const recentTimestamps = userTimestamps.filter(
    (timestamp) => now.getTime() - timestamp.getTime() < MESSAGE_LIMIT_DURATION
  );

  if (recentTimestamps.length < MESSAGE_LIMIT_COUNT) {
    // Add current timestamp to the list and save.
    recentTimestamps.push(now);
    messageTimestamps.set(username, recentTimestamps);
    return true;
  }

  return false;
}
