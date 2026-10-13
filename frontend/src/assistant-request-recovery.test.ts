import { afterEach, describe, expect, it, vi } from "vitest";
import {
  readPendingRequests,
  savePendingRequest,
  requestRecoveryBatch,
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
      expect(localStorage.getItem(localStorage.key(index)!)).toBe("1");
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
