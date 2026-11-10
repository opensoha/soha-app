import { afterEach, describe, expect, it, vi } from "vitest";
import {
  readPendingRequests,
  savePendingRequest,
  requestRecoveryBatch,
  pendingRequestState,
  markRunCancelling,
  acknowledgePendingRequest,
  discardUnacceptedRequest,
} from "./assistant-request-recovery";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});
describe("App request recovery journal", () => {
  it("keeps same-user requests on different services separate and stores only IDs", () => {
    const first = JSON.stringify(["service-A", "user"]),
      second = JSON.stringify(["service-B", "user"]);
    savePendingRequest(first, "session", "one");
    savePendingRequest(second, "session", "two");
    savePendingRequest(first, "session", "three");
    expect(readPendingRequests(first, "session")).toEqual(["one", "three"]);
    expect(readPendingRequests(second, "session")).toEqual(["two"]);
    expect(readPendingRequests(first, "another-session")).toEqual([]);
    for (let index = 0; index < localStorage.length; index++)
      expect(JSON.parse(localStorage.getItem(localStorage.key(index)!)!)).toEqual({cancelPending: false, acknowledged: false});
  });
  it("preserves unknown submissions at the limit and fails before a POST if storage is unavailable", () => {
    for (let index = 0; index < 65; index++)
      savePendingRequest("owner", "session", String(index));
    const ids = readPendingRequests("owner", "session");
    expect(ids).toHaveLength(65);
    expect(requestRecoveryBatch(ids, 0)).toHaveLength(64);
    expect(
      new Set([
        ...requestRecoveryBatch(ids, 0),
        ...requestRecoveryBatch(ids, 1),
      ]).size,
    ).toBe(65);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("unavailable");
    });
    expect(() => savePendingRequest("owner", "other", "one")).toThrow();
  });
});

it("imports exact legacy identities once without deleting old keys and latches cancellation", () => {
  const key = (owner: string, session: string, id: string, ns = "native-request.v1") =>
    `soha.app.${ns}:${encodeURIComponent(owner)}/${encodeURIComponent(session)}/${encodeURIComponent(id)}`;
  const owner = JSON.stringify(["https://service-A", "user"]);
  const legacy = key(owner, "session /", "request+");
  localStorage.setItem(legacy, JSON.stringify({cancelPending: true}));
  savePendingRequest(owner, "session /", "request+");
  expect(readPendingRequests(owner, "session /")).toEqual(["request+"]);
  expect(pendingRequestState(owner, "session /", "request+").cancelPending).toBe(true);
  expect(acknowledgePendingRequest(owner, "session /", "request+")).toBe(false);
  expect(readPendingRequests(JSON.stringify(["https://service-B", "user"]), "session /")).toEqual([]);
  expect(readPendingRequests(owner, "session")).toEqual([]);
  expect(readPendingRequests(owner, "session /")).toEqual(["request+"]);
  expect(acknowledgePendingRequest(owner, "session /", "request+", true)).toBe(true);
  expect(readPendingRequests(owner, "session /")).toEqual([]);
  expect(readPendingRequests(owner, "session /")).toEqual([]);
  expect(localStorage.getItem(legacy)).toBe(JSON.stringify({cancelPending: true}));
});
it("OR merges a mixed client's late cancellation and fails closed on corrupt entries", () => {
  const suffix = "owner/session/request";
  savePendingRequest("owner", "session", "request");
  acknowledgePendingRequest("owner", "session", "request");
  localStorage.setItem(`soha.app.native-request.v1:${suffix}`, JSON.stringify({cancelPending: true}));
  expect(readPendingRequests("owner", "session")).toEqual(["request"]);
  savePendingRequest("owner", "session", "request", false);
  expect(pendingRequestState("owner", "session", "request").cancelPending).toBe(true);
  localStorage.setItem(`soha.app.run-request.v2:${suffix}`, "invalid-json");
  expect(() => readPendingRequests("owner", "session")).toThrow();
});

it("imports the original v1 ID-only format without widening owner identity", () => {
  const oldKey = "soha.app.native-request.v1:server%2Fuser/session/id%2F1";
  localStorage.setItem(oldKey, "1");
  expect(readPendingRequests("server/user", "session")).toEqual(["id/1"]);
  expect(readPendingRequests("server", "session")).toEqual([]);
  expect(localStorage.getItem("soha.app.run-request.v2:server%2Fuser/session/id%2F1")).toBeTruthy();
  acknowledgePendingRequest("server/user", "session", "id/1");
  expect(readPendingRequests("server/user", "session")).toEqual([]);
  expect(localStorage.getItem(oldKey)).toBe("1");
});

it("persists cancellation after an acknowledged run is opened again", () => {
  savePendingRequest("server/user", "session", "request");
  acknowledgePendingRequest("server/user", "session", "request", false, "run");
  expect(readPendingRequests("server/user", "session")).toEqual([]);
  markRunCancelling("different-server/user", "session", "run");
  expect(readPendingRequests("server/user", "session")).toEqual([]);
  markRunCancelling("server/user", "session", "run");
  expect(readPendingRequests("server/user", "session")).toEqual(["request"]);
  expect(pendingRequestState("server/user", "session", "request")).toMatchObject({runId: "run", cancelPending: true});
  acknowledgePendingRequest("server/user", "session", "request", true, "run");
  expect(readPendingRequests("server/user", "session")).toEqual([]);
});

it("discards only an unaccepted canonical request without a Run or pending stop", () => {
  savePendingRequest("owner", "session", "pre-accept");
  savePendingRequest("owner", "session", "stopping", true);
  savePendingRequest("owner", "session", "accepted");
  acknowledgePendingRequest("owner", "session", "accepted", false, "run");
  localStorage.setItem("soha.app.native-request.v1:owner/session/legacy", "1");
  readPendingRequests("owner", "session");

  expect(discardUnacceptedRequest("owner", "session", "pre-accept")).toBe(true);
  for (const id of ["stopping", "accepted", "legacy"])
    expect(discardUnacceptedRequest("owner", "session", id)).toBe(false);
  expect(readPendingRequests("owner", "session")).toEqual(["legacy", "stopping"]);
});
