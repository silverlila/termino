export type ChannelCreated = {
  channelId: string;
  channelPassword: string;
};

export type MessageDelivered = {
  username: string;
  message: string;
};

export type SystemMessage = {
  message: string;
};

export type ErrorMessage = {
  message: string;
};
