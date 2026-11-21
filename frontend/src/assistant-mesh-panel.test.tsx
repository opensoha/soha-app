import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { ConfigProvider } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AssistantMeshPanel } from "@/assistant-mesh-panel";
import { meshApi } from "@/assistant-mesh-api";

vi.mock("@/assistant-mesh-api", () => ({
  meshApi: {
    profile: vi.fn(),
    setProfile: vi.fn(),
    search: vi.fn(),
    preview: vi.fn(),
    ask: vi.fn(),
    inquiries: vi.fn(),
    reply: vi.fn(),
    replyAndPublish: vi.fn(),
    draft: vi.fn(),
    create: vi.fn(),
    getAsset: vi.fn(),
    updateAsset: vi.fn(),
    assetAction: vi.fn(),
  },
}));

let root: Root;
let node: HTMLDivElement;
let client: QueryClient;

const profile = { open: false, away: false, intro: "", retentionDays: 7 };
const assistant = { ownerId: "owner-1", name: "发布助手", intro: "负责发布", away: false, topics: ["发布"] };
const inquiry = {
  id: "inquiry-1",
  callerId: "caller-1",
  ownerId: "user-1",
  callerName: "张三",
  ownerName: "我",
  question: "怎么上线？",
  status: "pending" as const,
  createdAt: "2026-11-21T01:00:00Z",
  dueAt: "2026-11-24T01:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("ResizeObserver", class { observe = vi.fn(); unobserve = vi.fn(); disconnect = vi.fn(); });
  vi.mocked(meshApi.profile).mockResolvedValue(profile);
  node = document.createElement("div");
  document.body.append(node);
  root = createRoot(node);
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});

afterEach(async () => {
  await act(async () => root.unmount());
  client.clear();
  node.remove();
  vi.unstubAllGlobals();
});

async function settle() {
  for (let index = 0; index < 2; index += 1) {
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 100)); });
  }
}

function button(label: string, contains = false) {
  const found = Array.from(document.querySelectorAll("button")).find((item) =>
    contains ? item.textContent?.includes(label) : item.textContent?.trim() === label,
  );
  expect(found).toBeDefined();
  return found!;
}

function input(value: string) {
  const element = document.querySelector<HTMLTextAreaElement>('[aria-label="仅回复该同事的内容"]')!;
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(element, value);
  element.dispatchEvent(new Event("input", { bubbles: true }));
}

async function render(initial: { key: number; tab: "find" | "inbox"; query?: string; question?: string }) {
  await act(async () => {
    root.render(
      <ConfigProvider>
        <QueryClientProvider client={client}>
          <AssistantMeshPanel
            owner="cache-user-1"
            userId="user-1"
            teams={["平台"]}
            projects={[]}
            open
            onClose={() => {}}
            initial={initial}
          />
        </QueryClientProvider>
      </ConfigProvider>,
    );
  });
  await settle();
}

it("keeps inbox replies private by default and ignores another owner's pending item", async () => {
  vi.mocked(meshApi.inquiries).mockResolvedValue([
    inquiry,
    { ...inquiry, id: "inquiry-2", ownerId: "other-user" },
  ]);
  vi.mocked(meshApi.reply).mockResolvedValue({ ...inquiry, status: "replied", answer: "按发布单执行" });
  await render({ key: 1, tab: "inbox" });
  expect(document.body.textContent).toContain("张三");
  expect(Array.from(document.querySelectorAll('[role="group"]')).length).toBe(1);
  await act(async () => button("回复该同事").click());
  await act(async () => input("按发布单执行"));
  await settle();
  await act(async () => button("仅回复该同事").click());
  await settle();

  expect(meshApi.reply).toHaveBeenCalledWith("inquiry-1", "按发布单执行");
  expect(meshApi.replyAndPublish).not.toHaveBeenCalled();
});

it("sends only the confirmed preview text with a stable request id", async () => {
  vi.mocked(meshApi.search).mockResolvedValue([assistant]);
  vi.mocked(meshApi.preview).mockResolvedValue({ question: "已确认的安全问题", blocked: false });
  vi.mocked(meshApi.ask).mockResolvedValue({ ...inquiry, callerId: "user-1", ownerId: "owner-1", callerName: "我" });
  vi.stubGlobal("crypto", { ...crypto, randomUUID: vi.fn(() => "request-1") });
  await render({ key: 2, tab: "find", query: "发布", question: "原始私人问题" });

  await act(async () => button("发布助手", true).click());
  await settle();
  await act(async () => button("预览发送内容").click());
  await settle();
  expect(meshApi.ask).not.toHaveBeenCalled();
  expect(document.body.textContent).toContain("已确认的安全问题");

  await act(async () => button("确认发送").click());
  await settle();
  expect(meshApi.ask).toHaveBeenCalledWith({ ownerId: "owner-1", requestId: "request-1", question: "已确认的安全问题" });
  expect(meshApi.ask).not.toHaveBeenCalledWith(expect.objectContaining({ question: "原始私人问题" }));
});
