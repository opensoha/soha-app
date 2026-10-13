import { afterEach, describe, expect, it, vi } from "vitest";
import { Blob as NodeBlob } from "node:buffer";
import { webcrypto } from "node:crypto";
import { setAccessToken } from "@/api";
import {
  assistantApi,
  parseAssistantFrames,
  streamAssistant,
} from "@/assistant-api";

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
});

describe("assistant streaming transport", () => {
  it("reads shared workspace state without dispatch and rejects foreign receipts", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({data:{assistantId:"mine", environmentVersion:9, latest:{id:"original"}}}))).mockResolvedValueOnce(new Response(JSON.stringify({data:{assistantId:"other"}}))).mockResolvedValueOnce(new Response(JSON.stringify({data:{assistantId:"mine",id:"different"}})));
    vi.stubGlobal("fetch",fetchMock);
    await expect(assistantApi.workspaceRuntime("mine")).resolves.toMatchObject({assistantId:"mine",environmentVersion:9});
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/copilot/assistant/environment/runtime");
    expect(fetchMock.mock.calls[0][1].method).toBeUndefined();
    await expect(assistantApi.workspaceRuntime("mine")).rejects.toMatchObject({code:"response_contract_mismatch"});
    await expect(assistantApi.runtimeReceipt("mine","original")).rejects.toMatchObject({code:"response_contract_mismatch"});
  });
  it.each([
    {
      name: "sessions",
      path: "/copilot/assistant/sessions",
      load: () => assistantApi.sessions(),
    },
    {
      name: "messages",
      path: "/copilot/sessions/owned/messages",
      load: () => assistantApi.messages("owned"),
    },
    {
      name: "tasks",
      path: "/copilot/assistant/tasks",
      load: () => assistantApi.tasks(),
    },
    {
      name: "artifacts",
      path: "/copilot/assistant/artifacts",
      load: () => assistantApi.artifacts(),
    },
  ])("reads $name from the Core list envelope", async ({ path, load }) => {
    const items = [{ id: "owned" }];
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ items })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: items })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: null })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: {} })))
      .mockResolvedValueOnce(new Response(JSON.stringify({})))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ items: Array(1001).fill(items[0]) })),
      );
    vi.stubGlobal("fetch", fetchMock);
    await expect(load()).resolves.toEqual(items);
    await expect(load()).resolves.toEqual(items);
    await expect(load()).resolves.toEqual([]);
    await expect(load()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    await expect(load()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    await expect(load()).rejects.toMatchObject({
      code: "response_contract_mismatch",
    });
    expect(
      fetchMock.mock.calls.every(([url]) => url === "/api/v1" + path),
    ).toBe(true);
    expect(
      fetchMock.mock.calls.every(([, init]) => init.method === undefined),
    ).toBe(true);
  });

  it("finds the original task with GET and preserves opaque request IDs", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            id: "original",
            sessionId: "session / 1",
            providerKind: "native",
          },
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await assistantApi.findRequest("session / 1", "opaque+key/id"),
    ).toMatchObject({ id: "original" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/sessions/session%20%2F%201/native-request?requestId=opaque%2Bkey%2Fid",
    );
    expect(fetchMock.mock.calls[0][1].method).toBeUndefined();
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: { sessionId: "foreign", providerKind: "native" },
        }),
      ),
    );
    await expect(
      assistantApi.findRequest("session / 1", "key"),
    ).rejects.toThrow("不匹配");
  });
  it("exports the selected version once, verifies bytes and never refresh-replays a denied export", async () => {
    vi.stubGlobal("Blob", NodeBlob);
    vi.stubGlobal("crypto", webcrypto);
    const input = { assistantId: "mine", environmentVersion: 3 };
    const body = "archive fixture";
    const digest = Array.from(
      new Uint8Array(
        await webcrypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(body),
        ),
      ),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(body, {
        headers: {
          "Content-Length": String(body.length),
          "X-Assistant-ID": "mine",
          "X-Content-SHA256": digest,
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const signal = new AbortController().signal;
    const blob = await assistantApi.exportEnvironmentData(input, signal);
    expect(await blob?.text()).toBe(body);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant/environment/export",
    );
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(input);
    fetchMock.mockResolvedValueOnce(
      new Response(body, {
        headers: {
          "Content-Length": String(body.length),
          "X-Assistant-ID": "mine",
          "X-Content-SHA256": "0".repeat(64),
        },
      }),
    );
    await expect(
      assistantApi.exportEnvironmentData(input, signal),
    ).rejects.toThrow("摘要不匹配");
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: { code: "unauthorized", message: "Denied fixture" },
        }),
        { status: 401 },
      ),
    );
    await expect(
      assistantApi.exportEnvironmentData(input, signal),
    ).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
  it("sends confirmed data deletion once and rejects a foreign receipt", async () => {
    const input = {
      assistantId: "mine",
      environmentVersion: 3,
      confirmationName: "Soha",
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { assistantId: "mine", state: "deleted" } }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { assistantId: "other", state: "deleted" } }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    await assistantApi.deleteEnvironmentData(input);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant/environment",
    );
    expect(fetchMock.mock.calls[0][1].method).toBe("DELETE");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(input);
    await expect(assistantApi.deleteEnvironmentData(input)).rejects.toThrow(
      "回执与助手不匹配",
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it("updates only assistant image fields and sends generation through the authenticated gateway", async () => {
    setAccessToken("test-access");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: { id: "mine", name: "Soha", avatarMotion: "off" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: [{ b64_json: "image-result" }] })),
      );
    vi.stubGlobal("fetch", fetchMock);
    await assistantApi.avatar({
      avatarUrl: "",
      avatarPosterUrl: "",
      avatarMotion: "off",
    });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/copilot/assistant/avatar");
    expect(fetchMock.mock.calls[0][1].method).toBe("PATCH");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      avatarUrl: "",
      avatarPosterUrl: "",
      avatarMotion: "off",
    });
    const signal = new AbortController().signal;
    await expect(
      assistantApi.generateAvatar("openai", "image-model", "robot", signal),
    ).resolves.toEqual({ data: [{ b64_json: "image-result" }] });
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/ai-gateway/llm/openai/v1/images/generations",
    );
    expect(fetchMock.mock.calls[1][1].signal.aborted).toBe(false);
    expect(signal.aborted).toBe(false);
    expect(
      new Headers(fetchMock.mock.calls[1][1].headers).get("Authorization"),
    ).toBe("Bearer test-access");
  });
  it("sends a selected lifecycle action once without caller-selected owner or node", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({ data: { assistantId: "mine", state: "sleeping" } }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    await assistantApi.changeEnvironment("mine", { action: "sleep" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      action: "sleep",
    });
  });
  it("uses GET for owned environment receipts and rejects foreign assistants", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              assistantId: "mine",
              state: "unknown",
              version: 1,
              dataInitialized: false,
            },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { assistantId: "other", state: "ready" } }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    await expect(assistantApi.environment("mine")).resolves.toMatchObject({
      state: "unknown",
    });
    await expect(assistantApi.environment("mine")).rejects.toThrow(
      "回执与助手不匹配",
    );
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/assistant/environment",
    );
    expect(fetchMock.mock.calls[0][1].method ?? "GET").toBe("GET");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it("accepts a successful empty memory deletion response", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      assistantApi.deleteMemory("memory:one"),
    ).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/ai/memory/memory%3Aone");
    expect(fetchMock.mock.calls[0][1].method).toBe("DELETE");
  });
  it("reads Native cursors and resumes the same run through authenticated transport", async () => {
    setAccessToken("test-access");
    const fetchMock = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            data: {
              items: [],
              nextSequence: 7,
              hasMore: false,
              resyncRequired: false,
            },
          }),
          { headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const signal = new AbortController().signal;
    await expect(
      assistantApi.events("native:run", 7, signal),
    ).resolves.toMatchObject({ nextSequence: 7 });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/copilot/agent-runs/native%3Arun/events?afterSequence=7",
    );
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(false);
    expect(signal.aborted).toBe(false);
    expect(
      new Headers(fetchMock.mock.calls[0][1].headers).get("Authorization"),
    ).toBe("Bearer test-access");
    await assistantApi.resume("native:run", { input: "今晚 22:00" });
    expect(fetchMock.mock.calls[1][0]).toBe(
      "/api/v1/copilot/agent-runs/native%3Arun/resume",
    );
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      input: "今晚 22:00",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each(["mixed run", "duplicate sequence", "non-progressing cursor"])(
    "rejects a %s event page",
    async (scenario) => {
      const event = {
        id: "event",
        runId: "native",
        sessionId: "main",
        sequence: 1,
        type: "message.delta",
        messageId: "reply",
        contentDelta: "evidence",
      };
      const page = {
        items: [event],
        nextSequence: 1,
        hasMore: false,
        resyncRequired: false,
      };
      if (scenario === "mixed run") event.runId = "other";
      if (scenario === "duplicate sequence") page.items.push({ ...event });
      if (scenario === "non-progressing cursor") {
        page.items = [];
        page.nextSequence = 0;
        page.hasMore = true;
      }
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: page }))),
      );
      await expect(assistantApi.events("native", 0)).rejects.toThrow(
        "Invalid task event",
      );
    },
  );
  it("preserves fragmented Unicode and authenticated Wails transport without replay", async () => {
    vi.stubGlobal("location", new URL("wails://localhost"));
    setAccessToken("test-access");
    const encoder = new TextEncoder();
    const bytes = encoder.encode(
      'data: {"id":"e1","sequence":1,"sessionId":"main","type":"message.delta","contentDelta":"你好"}\n\ndata: {"id":"e2","sequence":2,"sessionId":"main","type":"message.done","content":"你好"}\n\n',
    );
    const response = new Response(
      new ReadableStream({
        start(controller) {
          for (let i = 0; i < bytes.length; i += 2)
            controller.enqueue(bytes.slice(i, i + 2));
          controller.close();
        },
      }),
      { headers: { "content-type": "text/event-stream" } },
    );
    const fetchMock = vi.fn().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetchMock);
    const onEvent = vi.fn();
    await streamAssistant(
      "main",
      { content: "hello" },
      new AbortController().signal,
      onEvent,
    );
    expect(onEvent.mock.calls.map(([event]) => event.type)).toEqual([
      "message.delta",
      "message.done",
    ]);
    expect(onEvent.mock.calls[0][0].contentDelta).toBe("你好");
    const headers = new Headers(fetchMock.mock.calls[0][1].headers);
    expect(headers.get("Authorization")).toBe("Bearer test-access");
    expect(headers.get("Accept")).toBe("text/event-stream");
    expect(fetchMock.mock.calls[0][1].body).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects mixed sessions and interrupted replies without replaying a mutating request", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(
          new Response(
            'data: {"id":"e1","sequence":1,"sessionId":"other","type":"message.done","content":"private"}\n\n',
            { headers: { "content-type": "text/event-stream" } },
          ),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const onEvent = vi.fn();
    await expect(
      streamAssistant(
        "main",
        { content: "hello" },
        new AbortController().signal,
        onEvent,
      ),
    ).rejects.toThrow("conversation mismatch");
    expect(onEvent).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(() => parseAssistantFrames("data: {}\n\n")).toThrow(
      "Invalid assistant event",
    );
    fetchMock.mockResolvedValueOnce(
      new Response(
        'data: {"id":"e1","sequence":1,"sessionId":"main","type":"message.delta","contentDelta":"partial"}\n\n',
        { headers: { "content-type": "text/event-stream" } },
      ),
    );
    await expect(
      streamAssistant(
        "main",
        { content: "hello" },
        new AbortController().signal,
        onEvent,
      ),
    ).rejects.toThrow("ended unexpectedly");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

it("VM SSH uses the shared Core receipt and cancels the same command",async()=>{
 const fetchMock=vi.fn().mockImplementation(async () => new Response(JSON.stringify({data:{id:"original"}})));
 vi.stubGlobal("fetch",fetchMock);
 await assistantApi.vmSSHCommand("original/id");
 await assistantApi.cancelVMSSHCommand("original/id");
 expect(fetchMock.mock.calls.map(([url,init])=>[url,init.method||"GET"])).toEqual([["/api/v1/virtualization/ssh-commands/original%2Fid","GET"],["/api/v1/virtualization/ssh-commands/original%2Fid","DELETE"]]);
});
