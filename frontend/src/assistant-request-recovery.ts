import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueries, useQueryClient } from "@tanstack/react-query";
import type { WorkbenchAgentRun } from "@opensoha/contracts/gen/ts/sohaapi";
import { assistantApi } from "./assistant-api";

// The owner contains the service URL and principal ID. Each request is a separate entry:
// concurrent App windows cannot overwrite IDs. Never persist request contents or credentials.
const requestKey = (owner: string, session: string, request: string) =>
  `soha.app.native-request.v1:${encodeURIComponent(owner)}/${encodeURIComponent(session)}/${encodeURIComponent(request)}`;

export function readPendingRequests(owner?: string, session?: string) {
  if (!owner || !session) return [];
  const prefix = requestKey(owner, session, "");
  const ids: string[] = [];
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index);
    if (!key?.startsWith(prefix)) continue;
    const id = decodeURIComponent(key.slice(prefix.length));
    if (!id || id.length > 128)
      throw new Error("任务恢复标识不完整，请核对原会话");
    ids.push(id);
  }
  return ids.sort();
}

export function savePendingRequest(owner: string, session: string, id: string) {
  if (!owner || !session || !id || id.length > 128)
    throw new Error("无法保存任务恢复标识");
  localStorage.setItem(requestKey(owner, session, id), "1");
}

export function requestRecoveryBatch(ids: string[], page: number) {
  if (ids.length <= 64) return ids;
  const offset = (page * 64) % ids.length;
  return [...ids.slice(offset), ...ids.slice(0, offset)].slice(0, 64);
}

function removePendingRequest(owner: string, session: string, id: string) {
  try {
    const key = requestKey(owner, session, id);
    if (localStorage.getItem(key) === null) return false;
    localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

export function useRequestRecovery(
  owner: string | undefined,
  session: string,
  enabled: boolean,
) {
  const client = useQueryClient();
  const applied = useRef(new Set<string>());
  const [revision, setRevision] = useState(0);
  const [page, setPage] = useState(0);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    window.addEventListener("storage", refresh);
    return () => window.removeEventListener("storage", refresh);
  }, [refresh]);
  const journal = useMemo(() => {
    void revision;
    try {
      return { ids: readPendingRequests(owner, session), error: undefined };
    } catch {
      return { ids: [], error: "任务恢复标识读取失败，请核对原会话" };
    }
  }, [owner, session, revision]);
  useEffect(() => {
    if (!enabled || journal.ids.length <= 64) return;
    const timer = window.setInterval(() => setPage((value) => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [enabled, journal.ids.length]);
  const batch = requestRecoveryBatch(journal.ids, page);
  const queries = useQueries({
    queries: batch.map((id) => ({
      queryKey: ["assistant-native-request", owner, session, id],
      queryFn: () => assistantApi.findRequest(session, id),
      enabled: enabled && Boolean(owner && session),
      retry: false,
      refetchInterval: 5000,
    })),
  });
  useEffect(() => {
    if (!owner || !session) return;
    let changed = false;
    queries.forEach((query, index) => {
      const run = query.data;
      if (!run || !batch[index]) return;
      if (removePendingRequest(owner, session, batch[index])) changed = true;
      const receipt = JSON.stringify([owner, session, batch[index], run.id]);
      if (applied.current.has(receipt)) return;
      applied.current.add(receipt);
      client.setQueryData<WorkbenchAgentRun[]>(
        ["assistant-tasks", owner],
        (runs) => [...(runs ?? []).filter((item) => item.id !== run.id), run],
      );
      void client.invalidateQueries({
        queryKey: ["assistant-messages", owner, session],
      });
      changed = true;
    });
    if (changed) refresh();
  }, [client, queries, batch, owner, session, refresh]);
  return {
    pending: journal.ids.length > 0,
    error: journal.error,
    recheck: () => queries.forEach((query) => void query.refetch()),
    remember: (target: string, id: string) => {
      if (!owner) throw new Error("请先登录后分配任务");
      savePendingRequest(owner, target, id);
      refresh();
    },
    acknowledge: (target: string, id: string) => {
      if (owner) removePendingRequest(owner, target, id);
      refresh();
    },
  };
}
