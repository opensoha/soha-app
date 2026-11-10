import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueries, useQueryClient, type QueryKey } from "@tanstack/react-query";
import type { WorkbenchAgentRun } from "@opensoha/contracts/gen/ts/sohaapi";
import { assistantApi, isReadOnlyRun, isTerminalRun } from "./assistant-api";

// The owner contains the service URL and principal ID. Each request is a separate entry:
// concurrent App windows cannot overwrite IDs. Never persist request contents or credentials.
const namespace = "soha.app.run-request.v2:";
const legacyNamespace = "soha.app.native-request.v1:";
const stopNamespace = "soha.app.run-stop.v1:";
const requestKey = (owner: string, session: string, request: string, prefix = namespace) =>
  `${prefix}${encodeURIComponent(owner)}/${encodeURIComponent(session)}/${encodeURIComponent(request)}`;
type RequestState = { cancelPending: boolean; acknowledged: boolean; runId?: string };

function decodeState(value: string | null): RequestState {
  if (value === null || value === "1") return { cancelPending: false, acknowledged: false };
  const state = JSON.parse(value);
  if (!state || typeof state !== "object" || typeof state.cancelPending !== "boolean" ||
      (state.acknowledged !== undefined && typeof state.acknowledged !== "boolean") ||
      (state.runId !== undefined && (typeof state.runId !== "string" || !state.runId || state.runId.length > 256)))
    throw new Error("任务恢复标识不完整，请核对原会话");
  return { cancelPending: state.cancelPending, acknowledged: state.acknowledged === true, ...(state.runId ? {runId: state.runId} : {}) };
}

export function pendingRequestState(owner: string, session: string, id: string) {
  const current = decodeState(localStorage.getItem(requestKey(owner, session, id)));
  const legacy = decodeState(localStorage.getItem(requestKey(owner, session, id, legacyNamespace)));
  return { ...current, cancelPending: current.cancelPending || legacy.cancelPending,
    acknowledged: current.acknowledged && !(legacy.cancelPending && !current.cancelPending) };
}

function storedIDs(owner: string, session: string, prefix: string, maxLength: number) {
  const keyPrefix = requestKey(owner, session, "", prefix);
  const ids = [];
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index);
    if (!key?.startsWith(keyPrefix)) continue;
    const id = decodeURIComponent(key.slice(keyPrefix.length));
    if (!id || id.length > maxLength) throw new Error("任务恢复标识不完整，请核对原会话");
    ids.push(id);
  }
  return ids;
}

export function readPendingRequests(owner?: string, session?: string) {
  if (!owner || !session) return [];
  const ids = new Set([
    ...storedIDs(owner, session, legacyNamespace, 128),
    ...storedIDs(owner, session, namespace, 128),
  ]);
  return [...ids].sort().filter(id => {
    const state = pendingRequestState(owner, session, id);
    // Retain old keys for mixed clients; canonical receipts make import idempotent.
    localStorage.setItem(requestKey(owner, session, id), JSON.stringify(state));
    return !state.acknowledged;
  });
}

export function savePendingRequest(owner: string, session: string, id: string, cancelPending = false, runId?: string) {
  if (!owner || !session || !id || id.length > 128 || (runId && runId.length > 256))
    throw new Error("无法保存任务恢复标识");
  const previous = pendingRequestState(owner, session, id);
  if (previous.runId && runId && previous.runId !== runId)
    throw new Error("原任务回执与停止请求不匹配");
  localStorage.setItem(requestKey(owner, session, id), JSON.stringify({
    ...previous, acknowledged: false, cancelPending: previous.cancelPending || cancelPending,
    ...(runId ? {runId} : {}),
  }));
}

export function discardUnacceptedRequest(owner: string, session: string, id: string) {
  const key = requestKey(owner, session, id);
  try {
    if (localStorage.getItem(key) === null ||
        localStorage.getItem(requestKey(owner, session, id, legacyNamespace)) !== null)
      return false;
    const state = pendingRequestState(owner, session, id);
    if (state.acknowledged || state.cancelPending || state.runId) return false;
    localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

export function requestRecoveryBatch(ids: string[], page: number) {
  if (ids.length <= 64) return ids;
  const offset = (page * 64) % ids.length;
  return [...ids.slice(offset), ...ids.slice(0, offset)].slice(0, 64);
}

export function acknowledgePendingRequest(owner: string, session: string, id: string, terminal = false, runId?: string, readOnlyReconciled = false) {
  try {
    const state = pendingRequestState(owner, session, id);
    if (state.runId && runId && state.runId !== runId) return false;
    const next = { ...state, ...(runId ? {runId} : {}), acknowledged: state.acknowledged || readOnlyReconciled || !(state.cancelPending && !terminal) };
    if (JSON.stringify(state) === JSON.stringify(next)) return false;
    localStorage.setItem(requestKey(owner, session, id), JSON.stringify(next));
    return next.acknowledged;
  } catch {
    return false;
  }
}

export function markRunCancelling(owner: string, session: string, runId: string) {
  if (!owner || !session || !runId || runId.length > 256)
    throw new Error("无法保存任务停止标识");
  const requestId = storedIDs(owner, session, namespace, 128).find(
    id => pendingRequestState(owner, session, id).runId === runId,
  );
  if (requestId) {
    savePendingRequest(owner, session, requestId, true);
    return;
  }
  localStorage.setItem(requestKey(owner, session, runId, stopNamespace), "1");
}

function settleRunCancellation(owner: string, run: WorkbenchAgentRun) {
  if (!run.sessionId || (!isTerminalRun(run) && !isReadOnlyRun(run))) return false;
  try {
    const key = requestKey(owner, run.sessionId, run.id, stopNamespace);
    let changed = false;
    if (localStorage.getItem(key) !== null) {
      localStorage.removeItem(key);
      changed = true;
    }
    for (const id of storedIDs(owner, run.sessionId, namespace, 128)) {
      const state = pendingRequestState(owner, run.sessionId, id);
      if (state.runId !== run.id || !state.cancelPending || state.acknowledged) continue;
      if (acknowledgePendingRequest(owner, run.sessionId, id, isTerminalRun(run), run.id, isReadOnlyRun(run)))
        changed = true;
    }
    return changed;
  } catch {
    return false;
  }
}

export function useRequestRecovery(
  owner: string | undefined,
  session: string,
  enabled: boolean,
  taskQueryKey: QueryKey,
  runs: WorkbenchAgentRun[] | undefined,
  onRecovered: (run: WorkbenchAgentRun) => void,
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
      const ids = readPendingRequests(owner, session);
      const cancellations = owner && session ? [
        ...ids.flatMap(id => {
          const state = pendingRequestState(owner, session, id);
          return state.cancelPending ? [{requestId: id, runId: state.runId}] : [];
        }),
        ...storedIDs(owner, session, stopNamespace, 256).sort().map(runId => ({requestId: undefined, runId})),
      ] : [];
      return { ids, cancellations, error: undefined };
    } catch {
      return { ids: [], cancellations: [], error: "任务恢复标识读取失败，请核对原会话" };
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
      queryKey: ["assistant-run-request", owner, session, id],
      queryFn: () => assistantApi.findRequest(session, id),
      enabled: enabled && Boolean(owner && session),
      retry: false,
      refetchInterval: 5000,
    })),
  });
  useEffect(() => {
    if (!enabled || !owner || !session || journal.error) return;
    let changed = false;
    for (const run of runs ?? []) {
      if (run.sessionId === session && journal.cancellations.some(item => item.runId === run.id) &&
          settleRunCancellation(owner, run)) changed = true;
    }
    queries.forEach((query, index) => {
      const run = query.data;
      if (!run || !batch[index]) return;
      const state = pendingRequestState(owner, session, batch[index]);
      if (state.acknowledged || (state.runId && state.runId !== run.id)) return;
      const { cancelPending } = state;
      const terminal = isTerminalRun(run);
      const readOnly = isReadOnlyRun(run);
      if (acknowledgePendingRequest(owner, session, batch[index], terminal, run.id, readOnly)) changed = true;
      const receipt = JSON.stringify([owner, session, batch[index], run.id, cancelPending, run.status, readOnly]);
      if (applied.current.has(receipt)) return;
      applied.current.add(receipt);
      onRecovered(run);
      client.setQueryData<WorkbenchAgentRun[]>(
        taskQueryKey,
        (items) => items && [...items.filter((item) => item.id !== run.id), run],
      );
      changed = true;
    });
    if (changed) refresh();
  }, [client, queries, batch, owner, session, enabled, taskQueryKey, runs, journal, refresh, onRecovered]);
  return {
    pending: journal.ids.length > 0,
    cancellation: journal.cancellations[0],
    error: journal.error,
    recheck: () => queries.forEach((query) => void query.refetch()),
    remember: (target: string, id: string) => {
      if (!owner) throw new Error("请先登录后分配任务");
      savePendingRequest(owner, target, id);
      refresh();
    },
    markRunCancelling: (target: string, runId: string) => {
      if (!owner) throw new Error("请先登录后停止任务");
      markRunCancelling(owner, target, runId);
      refresh();
    },
    markCancelling: (target: string, id: string, runId?: string) => {
      if (!owner) throw new Error("请先登录后停止任务");
      savePendingRequest(owner, target, id, true, runId);
      refresh();
    },
    settleCancellation: (run: WorkbenchAgentRun) => {
      if (owner && settleRunCancellation(owner, run)) refresh();
    },
    discardUnaccepted: (target: string, id: string) => {
      if (!owner || !discardUnacceptedRequest(owner, target, id)) return false;
      refresh();
      return true;
    },
    acknowledge: (target: string, id: string, terminal = false, runId?: string, readOnly = false) => {
      if (owner) acknowledgePendingRequest(owner, target, id, terminal, runId, readOnly);
      refresh();
    },
  };
}
