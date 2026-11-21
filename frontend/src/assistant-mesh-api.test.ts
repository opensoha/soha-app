import { afterEach, describe, expect, it, vi } from "vitest";
import { setAccessToken } from "@/api";
import { meshApi } from "@/assistant-mesh-api";

const json = (body: unknown) => new Response(JSON.stringify(body));

const inquiry = {
  id: "inq-1",
  callerId: "me",
  ownerId: "owner-1",
  callerName: "我",
  ownerName: "同事",
  question: "怎么上线？",
  status: "pending",
  createdAt: "2026-11-21T01:00:00Z",
  dueAt: "2026-11-24T01:00:00Z",
};

const assistant = {
  ownerId: "owner-1",
  name: "发布助手",
  intro: "负责发布",
  away: false,
  topics: ["发布"],
};

const asset = { id: "asset-1", kind: "skill" };

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
});

describe("assistant mesh transport", () => {
  it("reads and saves the profile on the exact route", async () => {
    const profile = { open: true, away: false, intro: "在", retentionDays: 7 };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ data: profile }))
      .mockResolvedValueOnce(json({ data: profile }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(meshApi.profile()).resolves.toEqual(profile);
    await expect(
      meshApi.setProfile({ open: true, away: false, intro: "在" }),
    ).resolves.toEqual(profile);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant-mesh/profile",
    );
    expect(fetchMock.mock.calls[0][1].method).toBeUndefined();
    expect(fetchMock.mock.calls[1][1]).toMatchObject({
      method: "PUT",
      body: '{"open":true,"away":false,"intro":"在"}',
    });
    fetchMock.mockResolvedValueOnce(json({ data: { open: true } }));
    await expect(meshApi.profile()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
  });

  it("searches assistants with the Core list envelope and rejects sparse items", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ items: [assistant] }))
      .mockResolvedValueOnce(json({ items: null }))
      .mockResolvedValueOnce(json({ items: [{ ...assistant, topics: null }] }))
      .mockResolvedValueOnce(json({ items: {} }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(meshApi.search()).resolves.toEqual([assistant]);
    await expect(meshApi.search("发布")).resolves.toEqual([]);
    await expect(meshApi.search()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    await expect(meshApi.search()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    expect(
      fetchMock.mock.calls.every(
        ([url]) =>
          url === "/api/v1/copilot/assistant-mesh/assistants/search",
      ),
    ).toBe(true);
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: "{}",
    });
    expect(fetchMock.mock.calls[1][1].body).toBe('{"query":"发布"}');
  });

  it("previews and asks with exact routes, preserving owner receipts", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ data: { question: "怎么上线？", blocked: false } }))
      .mockResolvedValueOnce(json({ data: inquiry }))
      .mockResolvedValueOnce(json({ data: { ...inquiry, ownerId: "other" } }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(meshApi.preview("怎么上线？")).resolves.toEqual({
      question: "怎么上线？",
      blocked: false,
    });
    const input = { ownerId: "owner-1", requestId: "req-1", question: "怎么上线？" };
    await expect(meshApi.ask(input)).resolves.toMatchObject({ id: "inq-1" });
    await expect(meshApi.ask(input)).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries/preview",
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: '{"question":"怎么上线？"}',
    });
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries",
    );
    expect(fetchMock.mock.calls[1][1].body).toBe(JSON.stringify(input));
  });

  it("lists both inquiry directions and narrows status decoding", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ items: [inquiry] }))
      .mockResolvedValueOnce(json({ items: null }))
      .mockResolvedValueOnce(json({ items: [{ ...inquiry, status: "weird" }] }))
      .mockResolvedValueOnce(json({ items: [{ ...inquiry, citations: {} }] }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(meshApi.inquiries("sent")).resolves.toEqual([inquiry]);
    await expect(meshApi.inquiries("inbox")).resolves.toEqual([]);
    await expect(meshApi.inquiries("sent")).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    await expect(meshApi.inquiries("inbox")).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries?direction=sent",
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries?direction=inbox",
    );
    expect(fetchMock.mock.calls[0][1].method).toBeUndefined();
  });

  it("replies and replies with publication on the exact inquiry routes", async () => {
    const answered = { ...inquiry, id: "inq / 1", status: "replied", answer: "这样做" };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ data: answered }))
      .mockResolvedValueOnce(json({ data: answered }))
      .mockResolvedValueOnce(json({ data: { ...answered, id: "other" } }))
      .mockResolvedValueOnce(json({ data: inquiry }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(meshApi.reply("inq / 1", "这样做")).resolves.toMatchObject({
      id: "inq / 1",
    });
    const share = {
      answer: "这样做",
      title: "发布经验",
      summary: "上线步骤",
      kind: "experience_card" as const,
      audience: { visibility: "organization" as const },
    };
    await expect(
      meshApi.replyAndPublish("inq / 1", share),
    ).resolves.toMatchObject({ id: "inq / 1" });
    await expect(
      meshApi.replyAndPublish("inq / 1", share),
    ).rejects.toMatchObject({ code: "response_contract_mismatch" });
    await expect(meshApi.reply("inq-1", "这样做")).resolves.toMatchObject({
      id: "inq-1",
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries/inq%20%2F%201/reply",
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: '{"answer":"这样做"}',
    });
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/copilot/assistant-mesh/inquiries/inq%20%2F%201/reply-and-publish",
    );
    expect(fetchMock.mock.calls[1][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify(share),
    });
  });

  it("uses exact asset routes and guards deterministic asset IDs", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ data: asset }))
      .mockResolvedValueOnce(json({ data: asset }))
      .mockResolvedValueOnce(json({ data: asset }))
      .mockResolvedValueOnce(json({ data: asset }))
      .mockResolvedValueOnce(json({ data: { asset, runId: "run-1" } }))
      .mockResolvedValueOnce(json({ data: { ...asset, id: "other" } }))
      .mockResolvedValueOnce(json({ data: { ...asset, id: "other" } }))
      .mockResolvedValueOnce(json({ data: { asset: { ...asset, id: "other" } } }))
      .mockResolvedValueOnce(json({ data: {} }))
      .mockResolvedValueOnce(json({ data: { ...asset, kind: "unknown" } }));
    vi.stubGlobal("fetch", fetchMock);
    const input = {
      kind: "skill" as const,
      title: "发布",
      body: "步骤",
    };
    const extract = {
      sessionId: "session-1",
      title: "发布",
      kind: "skill" as const,
      messageIds: ["message-1"],
    };
    await expect(meshApi.draft(extract)).resolves.toEqual(asset);
    await expect(meshApi.create(input)).resolves.toEqual(asset);
    await expect(meshApi.getAsset("asset-1")).resolves.toEqual(asset);
    await expect(
      meshApi.updateAsset("asset-1", "digest-1", input),
    ).resolves.toEqual(asset);
    await expect(
      meshApi.assetAction("asset-1", "publish", {
        expectedDigest: "digest-1",
        lifetimeHours: 24,
      }),
    ).resolves.toEqual({ asset, runId: "run-1" });
    await expect(meshApi.getAsset("asset-1")).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    await expect(
      meshApi.updateAsset("asset-1", "digest-1", input),
    ).rejects.toMatchObject({ code: "response_contract_mismatch" });
    await expect(
      meshApi.assetAction("asset-1", "trial", { expectedDigest: "digest-1" }),
    ).rejects.toMatchObject({ code: "response_contract_mismatch" });
    await expect(
      meshApi.assetAction("asset-1", "revoke", { expectedDigest: "digest-1" }),
    ).rejects.toMatchObject({ code: "response_contract_mismatch" });
    await expect(meshApi.getAsset("asset-1")).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant-mesh/assets/extract",
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify(extract),
    });
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/copilot/assistant-mesh/assets",
    );
    expect(fetchMock.mock.calls[1][1]).toMatchObject({
      method: "POST",
      body: JSON.stringify(input),
    });
    expect(fetchMock.mock.calls[2][0]).toBe(
      "/api/v1/copilot/assistant-mesh/assets/asset-1",
    );
    expect(fetchMock.mock.calls[2][1].method).toBeUndefined();
    expect(fetchMock.mock.calls[3][0]).toBe(
      "/api/v1/copilot/assistant-mesh/assets/asset-1",
    );
    expect(fetchMock.mock.calls[3][1]).toMatchObject({
      method: "PUT",
      body: JSON.stringify({ expectedDigest: "digest-1", input }),
    });
    expect(fetchMock.mock.calls[4][0]).toBe(
      "/api/v1/copilot/assistant-mesh/assets/asset-1/actions/publish",
    );
    expect(fetchMock.mock.calls[4][1]).toMatchObject({
      method: "POST",
      body: '{"expectedDigest":"digest-1","lifetimeHours":24}',
    });
    expect(
      fetchMock.mock.calls.every(([, init]) => init.credentials === "include"),
    ).toBe(true);
  });
});
