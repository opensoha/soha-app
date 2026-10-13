import { useState } from "react";
import { Button, Dropdown, Typography } from "antd";
import { EditOutlined, PictureOutlined } from "@ant-design/icons";
import type { PersonalAssistant } from "./assistant-api";
export function AssistantAvatar({
  assistant,
  busy = false,
}: {
  assistant?: PersonalAssistant;
  busy?: boolean;
}) {
  const [failed, setFailed] = useState("");
  const image = assistant?.avatarUrl || "/heya-avatar.svg";
  const source = failed === image ? "/heya-avatar.svg" : image;
  const poster =
    failed === image ? source : assistant?.avatarPosterUrl || source;
  return (
    <picture
      className={`app-assistant-avatar ${source === "/heya-avatar.svg" ? "is-default" : ""} ${busy && assistant?.avatarMotion !== "off" ? "is-busy" : ""}`}
    >
      <source media="(prefers-reduced-motion: reduce)" srcSet={poster} />
      <img
        alt=""
        src={assistant?.avatarMotion === "off" ? poster : source}
        onError={() => setFailed(image)}
      />
    </picture>
  );
}

export function AssistantProfile({
  assistant,
  busy,
  onPrompt,
}: {
  assistant: PersonalAssistant;
  busy: boolean;
  onPrompt: (kind: "name" | "avatar") => void;
}) {
  return (
    <div className="app-assistant-profile">
      <div className="app-assistant-profile-picture">
        <AssistantAvatar assistant={assistant} busy={busy} />
        <Dropdown
          disabled={busy}
          trigger={["click"]}
          menu={{
            items: [
              { key: "avatar", label: "更改形象", icon: <PictureOutlined /> },
              { key: "name", label: "编辑昵称", icon: <EditOutlined /> },
            ],
            onClick: ({ key }) =>
              onPrompt(key === "avatar" ? "avatar" : "name"),
          }}
        >
          <Button
            disabled={busy}
            type="text"
            shape="circle"
            icon={<EditOutlined />}
            aria-label="编辑助手资料"
          />
        </Dropdown>
      </div>
      <Typography.Title level={4}>{assistant.name}</Typography.Title>
    </div>
  );
}
