import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VMSSHCommandProgress } from "@/assistant-vm-access";
import { assistantApi } from "@/assistant-api";
import { useAppStore } from "@/store";

vi.mock("@/assistant-api", () => ({assistantApi:{vmSSHCommand:vi.fn(),vmAccessBinding:vi.fn(),cancelVMSSHCommand:vi.fn()}}));
let root: Root;
let node: HTMLDivElement;
let client: QueryClient;
const receipt = { id: "original-command", vmId: "vm-one", bindingRevision: 2, status: "running", outcome: "unknown" as const, terminal: false };
beforeEach(() => {
 vi.clearAllMocks();
 vi.mocked(assistantApi.vmSSHCommand).mockResolvedValue(receipt);
 vi.mocked(assistantApi.vmAccessBinding).mockResolvedValue({vmId:"vm-one",revision:3,username:"soha",credentialRef:"soha://secrets/key/versions/1"} as Awaited<ReturnType<typeof assistantApi.vmAccessBinding>>);
 vi.mocked(assistantApi.cancelVMSSHCommand).mockResolvedValue({...receipt,status:"canceled",terminal:true});
 node=document.createElement("div");document.body.appendChild(node);root=createRoot(node);
 client=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}});
});
afterEach(async()=>{await act(async()=>root.unmount());client.clear();node.remove();useAppStore.setState({bootstrap:null});});
async function render(permissionKeys:string[]){
 useAppStore.setState({bootstrap:{currentUser:{userId:"user-one"},permissionSnapshot:{permissionKeys}} as NonNullable<ReturnType<typeof useAppStore.getState>["bootstrap"]>});
 await act(async()=>{root.render(<QueryClientProvider client={client}><VMSSHCommandProgress commandID="original-command"/></QueryClientProvider>);await new Promise(resolve=>setTimeout(resolve,30));});
 await act(async()=>{await new Promise(resolve=>setTimeout(resolve,20));});
}
describe("shared VM SSH receipt",()=>{
 it("gates the binding with view permission and cancels the original command",async()=>{
  await render(["virtualization.vms.connect","secret.use"]);
  expect(assistantApi.vmAccessBinding).not.toHaveBeenCalled();
  const cancel=Array.from(node.querySelectorAll("button")).find(button=>button.textContent?.includes("取消原 SSH 任务"));
  expect(cancel).toBeDefined();
  await act(async()=>{cancel?.click();await new Promise(resolve=>setTimeout(resolve,30));});
  expect(assistantApi.cancelVMSSHCommand).toHaveBeenCalledWith("original-command");
  expect(node.textContent).toContain("不会自动重跑");
  expect(node.textContent).not.toContain("取消原 SSH 任务");
 });
 it("shows the fixed credential version and keeps SSH success separate from personal readiness",async()=>{
  vi.mocked(assistantApi.vmSSHCommand).mockResolvedValue({...receipt,status:"completed",outcome:"succeeded",terminal:true,exitCode:0});
  await render(["virtualization.vms.view","virtualization.vms.connect","secret.use"]);
  expect(assistantApi.vmAccessBinding).toHaveBeenCalledWith("vm-one",expect.any(AbortSignal));
  for(let attempt=0;attempt<20&&!node.textContent?.includes("soha://secrets/key/versions/1");attempt++) {await act(async()=>{await new Promise(resolve=>setTimeout(resolve,20));});}
  expect(node.textContent).toContain("soha://secrets/key/versions/1");
  expect(node.textContent).toContain("原绑定版本 2 / 当前 3");
  expect(node.textContent).toContain("完整就绪能力由服务端单独验收");
  expect(assistantApi.cancelVMSSHCommand).not.toHaveBeenCalled();
 });
});
