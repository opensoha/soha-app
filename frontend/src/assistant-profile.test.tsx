import { act } from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider } from "antd";
import { expect, it, vi } from "vitest";
import { AssistantProfile, AssistantAvatar } from "./assistant-profile";
import { prepareAssistantAvatar } from "./assistant-avatar-image";

it("opens chat customization prompts without a modal and keeps the static poster", async () => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = vi.fn();
      unobserve = vi.fn();
      disconnect = vi.fn();
    },
  );
  const node = document.createElement("div");
  document.body.append(node);
  const root = createRoot(node);
  const onPrompt = vi.fn();
  const assistant = {
    id: "mine",
    name: "小禾",
    mainSessionId: "main",
    createdAt: "",
    updatedAt: "",
    avatarUrl: "data:image/gif;base64,animated",
    avatarPosterUrl: "data:image/png;base64,poster",
    avatarMotion: "off" as const,
  };
  const click = async (selector: string) => {
    await act(async () => {
      document.querySelector<HTMLElement>(selector)!.click();
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
  };
  try {
    await act(async () => {
      root.render(
        <ConfigProvider>
          <AssistantProfile
            assistant={assistant}
            busy={false}
            onPrompt={onPrompt}
          />
          <AssistantAvatar assistant={assistant} />
        </ConfigProvider>,
      );
    });
    expect(node.querySelector("picture img")?.getAttribute("src")).toBe(
      assistant.avatarPosterUrl,
    );
    await click('[aria-label="编辑助手资料"]');
    await click('.ant-dropdown-menu-item[data-menu-id$="avatar"]');
    expect(onPrompt).toHaveBeenCalledWith("avatar");
    expect(document.querySelector(".ant-modal")).toBeNull();
    expect(node.textContent).toContain("小禾");
    await expect(
      prepareAssistantAvatar(new Blob(["<svg/>"], { type: "image/svg+xml" })),
    ).rejects.toThrow("支持 PNG");
    await expect(
      prepareAssistantAvatar(
        new Blob([new Uint8Array(512 * 1024 + 1)], { type: "image/gif" }),
      ),
    ).rejects.toThrow("512KB");
  } finally {
    await act(async () => root.unmount());
    node.remove();
    vi.unstubAllGlobals();
  }
});
