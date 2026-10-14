export interface InvitePanelProps {
  invite: string;
}

export function InvitePanel({ invite }: InvitePanelProps) {
  return (
    <box
      style={{
        flexDirection: "column",
        flexShrink: 0,
        border: true,
        borderColor: "#e0a35c",
        paddingLeft: 1,
        paddingRight: 1,
      }}
      title="your invite"
    >
      <text style={{ fg: "#c8d3f5" }} wrapMode="char">
        {invite}
      </text>
      <text style={{ fg: "#8b93a8" }} wrapMode="word">
        give it to the other person by a route you trust — anyone holding it can join · /copy copies it
      </text>
    </box>
  );
}
