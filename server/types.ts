export type CreateChannelPayload = {
  channelId: string;
  channelPassword: string;
  username: string;
};

export type JoinChannelPayload = {
  channelId: string;
  channelPassword: string;
  username: string;
};

export type MessagePayload = {
  message: string;
};
