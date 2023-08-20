function generateSecureRandomString(length: number): string {
  const array = new Uint8Array(length);
  const cryptoArray = crypto.getRandomValues(array);
  return [...cryptoArray].map((byte) => byte.toString(36).charAt(0)).join("");
}

export function generateUsername(): string {
  return `user_${generateSecureRandomString(5)}`;
}

export function generatePassword(): string {
  return `pass_${generateSecureRandomString(32)}`;
}

export function generateSecurityPassphrase(): string {
  return generateSecureRandomString(32);
}

export function generateChannelId(): string {
  return generateSecureRandomString(16);
}

export async function generateHashKey(
  channelId: string,
  password: string
): Promise<string> {
  const data = new TextEncoder().encode(channelId + password);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hashHex;
}
