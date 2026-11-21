import { ApiError, assistantRequest, requestResponse } from "@/api";

export type MeshAssetKind = "skill" | "experience_card" | "work_pulse";
export type MeshInquiryStatus =
  | "processing"
  | "pending"
  | "answered"
  | "replied"
  | "expired"
  | "invalidated";

export interface MeshProfile {
  open: boolean;
  away: boolean;
  intro: string;
  retentionDays: number;
}

export interface MeshProfileInput {
  open: boolean;
  away: boolean;
  intro: string;
}

export interface MeshAssistant {
  ownerId: string;
  name: string;
  intro: string;
  away: boolean;
  topics: string[];
}

export interface MeshQuestionPreview {
  question: string;
  blocked: boolean;
}

export interface MeshInquiryCitation {
  assetId: string;
  version: number;
  title: string;
  observedAt: string;
}

export interface MeshInquiry {
  id: string;
  callerId: string;
  ownerId: string;
  callerName: string;
  ownerName: string;
  question: string;
  status: MeshInquiryStatus;
  answer?: string;
  citations?: MeshInquiryCitation[];
  createdAt: string;
  dueAt: string;
  closedAt?: string;
}

export interface MeshInquiryInput {
  ownerId: string;
  requestId: string;
  question: string;
}

export interface MeshAudience {
  visibility: "private" | "teams" | "projects" | "organization";
  teams?: string[];
  projects?: string[];
}

export interface MeshShareReply {
  answer: string;
  title: string;
  summary: string;
  kind: "experience_card" | "work_pulse";
  audience: MeshAudience;
  lifetimeHours?: number;
  lifetimeDays?: number;
  workStatus?: string;
}

export interface MeshAssetInput {
  kind: MeshAssetKind;
  title: string;
  body: string;
  applicability?: string;
  workStatus?: string;
  blockerReason?: string;
}

export type MeshExtract = {
  sessionId: string;
  title: string;
  kind: "skill" | "experience_card";
} & (
  | { runId: string; messageIds?: never }
  | { messageIds: string[]; runId?: never }
);

export interface MeshAssetVersion {
  input: MeshAssetInput;
  digest: string;
  version: number;
  audience: MeshAudience;
  expiresAt?: string;
  publishedAt?: string;
}

export interface MeshAssetTrial {
  runId: string;
  digest: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled" | "expired";
}

export interface MeshAssetReview {
  status: "pending" | "approved" | "rejected" | "withdrawn";
  reason?: string;
  candidate?: MeshAssetVersion;
}

export interface MeshAsset {
  id: string;
  kind: MeshAssetKind | "mcp";
  draft?: MeshAssetInput;
  draftDigest?: string;
  published?: MeshAssetVersion;
  trial?: MeshAssetTrial;
  review?: MeshAssetReview;
}

export interface MeshAssetActionInput {
  expectedDigest?: string;
  audience?: MeshAudience;
  lifetimeHours?: number;
  lifetimeDays?: number;
  permanent?: boolean;
  reason?: string;
  sessionId?: string;
  requestId?: string;
  prompt?: string;
  parameters?: Record<string, string | number | boolean>;
  resourceId?: string;
}

export interface MeshAssetActionResult {
  asset?: MeshAsset;
  runId?: string;
}

type MeshAssetAction = "trial" | "publish" | "revoke";

const inquiryStatuses = new Set<MeshInquiryStatus>([
  "processing",
  "pending",
  "answered",
  "replied",
  "expired",
  "invalidated",
]);
const assetKinds = new Set(["skill", "experience_card", "work_pulse", "mcp"]);
const trialStatuses = new Set([
  "queued",
  "running",
  "completed",
  "failed",
  "canceled",
  "expired",
]);
const reviewStatuses = new Set(["pending", "approved", "rejected", "withdrawn"]);

function mismatch(message: string): never {
  throw new ApiError(502, "response_contract_mismatch", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeProfile(value: unknown): MeshProfile {
  if (
    !isRecord(value) ||
    typeof value.open !== "boolean" ||
    typeof value.away !== "boolean" ||
    typeof value.intro !== "string" ||
    !Number.isSafeInteger(value.retentionDays) ||
    (value.retentionDays as number) < 0
  )
    return mismatch("接待设置回执不完整");
  return value as unknown as MeshProfile;
}

function decodeAssistant(value: unknown): MeshAssistant {
  if (
    !isRecord(value) ||
    typeof value.ownerId !== "string" ||
    typeof value.name !== "string" ||
    typeof value.intro !== "string" ||
    typeof value.away !== "boolean" ||
    !Array.isArray(value.topics) ||
    !value.topics.every((topic) => typeof topic === "string")
  )
    return mismatch("助手列表回执不完整");
  return value as unknown as MeshAssistant;
}

function decodePreview(value: unknown): MeshQuestionPreview {
  if (
    !isRecord(value) ||
    typeof value.question !== "string" ||
    typeof value.blocked !== "boolean"
  )
    return mismatch("询问预览回执不完整");
  return value as unknown as MeshQuestionPreview;
}

function decodeCitations(value: unknown): MeshInquiryCitation[] {
  if (
    !Array.isArray(value) ||
    !value.every(
      (citation) =>
        isRecord(citation) &&
        typeof citation.assetId === "string" &&
        Number.isSafeInteger(citation.version) &&
        typeof citation.title === "string" &&
        typeof citation.observedAt === "string",
    )
  )
    return mismatch("询问引用回执不完整");
  return value as unknown as MeshInquiryCitation[];
}

function decodeInquiry(value: unknown): MeshInquiry {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.callerId !== "string" ||
    typeof value.ownerId !== "string" ||
    typeof value.callerName !== "string" ||
    typeof value.ownerName !== "string" ||
    typeof value.question !== "string" ||
    typeof value.status !== "string" ||
    !inquiryStatuses.has(value.status as MeshInquiryStatus) ||
    typeof value.createdAt !== "string" ||
    typeof value.dueAt !== "string" ||
    (value.answer !== undefined && typeof value.answer !== "string") ||
    (value.closedAt !== undefined && typeof value.closedAt !== "string")
  )
    return mismatch("询问回执不完整");
  if (value.citations !== undefined) decodeCitations(value.citations);
  return value as unknown as MeshInquiry;
}

function decodeAudience(value: unknown): MeshAudience {
  if (
    !isRecord(value) ||
    !["private", "teams", "projects", "organization"].includes(
      value.visibility as string,
    ) ||
    (value.teams !== undefined &&
      (!Array.isArray(value.teams) ||
        !value.teams.every((team) => typeof team === "string"))) ||
    (value.projects !== undefined &&
      (!Array.isArray(value.projects) ||
        !value.projects.every((project) => typeof project === "string")))
  )
    return mismatch("发布范围回执不完整");
  return value as unknown as MeshAudience;
}

function decodeAssetInput(value: unknown): MeshAssetInput {
  if (
    !isRecord(value) ||
    typeof value.kind !== "string" ||
    !assetKinds.has(value.kind) ||
    typeof value.title !== "string" ||
    typeof value.body !== "string" ||
    (value.applicability !== undefined && typeof value.applicability !== "string") ||
    (value.workStatus !== undefined && typeof value.workStatus !== "string") ||
    (value.blockerReason !== undefined && typeof value.blockerReason !== "string")
  )
    return mismatch("资产内容回执不完整");
  return value as unknown as MeshAssetInput;
}

function decodeVersion(value: unknown): MeshAssetVersion {
  if (
    !isRecord(value) ||
    typeof value.digest !== "string" ||
    !Number.isSafeInteger(value.version) ||
    (value.expiresAt !== undefined && typeof value.expiresAt !== "string") ||
    (value.publishedAt !== undefined && typeof value.publishedAt !== "string")
  )
    return mismatch("资产版本回执不完整");
  decodeAssetInput(value.input);
  decodeAudience(value.audience);
  return value as unknown as MeshAssetVersion;
}

function decodeTrial(value: unknown): MeshAssetTrial {
  if (
    !isRecord(value) ||
    typeof value.runId !== "string" ||
    typeof value.digest !== "string" ||
    typeof value.status !== "string" ||
    !trialStatuses.has(value.status)
  )
    return mismatch("资产试运行回执不完整");
  return value as unknown as MeshAssetTrial;
}

function decodeReview(value: unknown): MeshAssetReview {
  if (
    !isRecord(value) ||
    typeof value.status !== "string" ||
    !reviewStatuses.has(value.status) ||
    (value.reason !== undefined && typeof value.reason !== "string")
  )
    return mismatch("资产审核回执不完整");
  if (value.candidate !== undefined) decodeVersion(value.candidate);
  return value as unknown as MeshAssetReview;
}

function decodeAsset(value: unknown): MeshAsset {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.kind !== "string" ||
    !assetKinds.has(value.kind) ||
    (value.draftDigest !== undefined && typeof value.draftDigest !== "string")
  )
    return mismatch("资产回执不完整");
  if (value.draft !== undefined) decodeAssetInput(value.draft);
  if (value.published !== undefined) decodeVersion(value.published);
  if (value.trial !== undefined) decodeTrial(value.trial);
  if (value.review !== undefined) decodeReview(value.review);
  return value as unknown as MeshAsset;
}

function decodeActionResult(value: unknown): MeshAssetActionResult {
  if (!isRecord(value) || (value.asset === undefined && value.runId === undefined))
    return mismatch("资产操作回执不完整");
  if (value.runId !== undefined && typeof value.runId !== "string")
    return mismatch("资产操作回执不完整");
  if (value.asset !== undefined) decodeAsset(value.asset);
  return value as unknown as MeshAssetActionResult;
}

async function meshList(
  path: string,
  init: RequestInit = {},
): Promise<unknown[]> {
  const payload = (await (await requestResponse(path, init)).json()) as {
    items?: unknown[] | null;
    data?: unknown[];
  } | null;
  // Existing Core versions encode empty Go slices as null.
  const items = payload?.items === null ? [] : (payload?.items ?? payload?.data);
  if (!Array.isArray(items) || items.length > 1000)
    return mismatch("列表回执不完整");
  return items;
}

export const meshApi = {
  profile: async () =>
    decodeProfile(
      await assistantRequest("/copilot/assistant-mesh/profile"),
    ),
  setProfile: async (input: MeshProfileInput) =>
    decodeProfile(
      await assistantRequest("/copilot/assistant-mesh/profile", {
        method: "PUT",
        body: JSON.stringify(input),
      }),
    ),
  search: async (query?: string) =>
    (
      await meshList("/copilot/assistant-mesh/assistants/search", {
        method: "POST",
        body: JSON.stringify(query === undefined ? {} : { query }),
      })
    ).map(decodeAssistant),
  preview: async (question: string) =>
    decodePreview(
      await assistantRequest("/copilot/assistant-mesh/inquiries/preview", {
        method: "POST",
        body: JSON.stringify({ question }),
      }),
    ),
  ask: async (input: MeshInquiryInput) => {
    const inquiry = decodeInquiry(
      await assistantRequest("/copilot/assistant-mesh/inquiries", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    );
    if (inquiry.ownerId !== input.ownerId)
      mismatch("询问回执与助手不匹配");
    return inquiry;
  },
  inquiries: async (direction: "sent" | "inbox") =>
    (
      await meshList(
        `/copilot/assistant-mesh/inquiries?direction=${encodeURIComponent(direction)}`,
      )
    ).map(decodeInquiry),
  reply: async (id: string, answer: string) => {
    const inquiry = decodeInquiry(
      await assistantRequest(
        `/copilot/assistant-mesh/inquiries/${encodeURIComponent(id)}/reply`,
        { method: "POST", body: JSON.stringify({ answer }) },
      ),
    );
    if (inquiry.id !== id) mismatch("回复回执与询问不匹配");
    return inquiry;
  },
  replyAndPublish: async (id: string, input: MeshShareReply) => {
    const inquiry = decodeInquiry(
      await assistantRequest(
        `/copilot/assistant-mesh/inquiries/${encodeURIComponent(id)}/reply-and-publish`,
        { method: "POST", body: JSON.stringify(input) },
      ),
    );
    if (inquiry.id !== id) mismatch("回复发布回执与询问不匹配");
    return inquiry;
  },
  draft: async (input: MeshExtract) =>
    decodeAsset(
      await assistantRequest("/copilot/assistant-mesh/assets/extract", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    ),
  create: async (input: MeshAssetInput) =>
    decodeAsset(
      await assistantRequest("/copilot/assistant-mesh/assets", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    ),
  getAsset: async (id: string) => {
    const asset = decodeAsset(
      await assistantRequest(
        `/copilot/assistant-mesh/assets/${encodeURIComponent(id)}`,
      ),
    );
    if (asset.id !== id) mismatch("资产回执与资产不匹配");
    return asset;
  },
  updateAsset: async (
    id: string,
    expectedDigest: string,
    input: MeshAssetInput,
  ) => {
    const asset = decodeAsset(
      await assistantRequest(
        `/copilot/assistant-mesh/assets/${encodeURIComponent(id)}`,
        {
          method: "PUT",
          body: JSON.stringify({ expectedDigest, input }),
        },
      ),
    );
    if (asset.id !== id) mismatch("资产回执与资产不匹配");
    return asset;
  },
  assetAction: async (
    id: string,
    action: MeshAssetAction,
    input: MeshAssetActionInput,
  ) => {
    const result = decodeActionResult(
      await assistantRequest(
        `/copilot/assistant-mesh/assets/${encodeURIComponent(id)}/actions/${action}`,
        { method: "POST", body: JSON.stringify(input) },
      ),
    );
    if (result.asset !== undefined && result.asset.id !== id)
      mismatch("资产操作回执与资产不匹配");
    return result;
  },
};
