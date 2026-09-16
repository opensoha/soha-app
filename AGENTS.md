# Soha App 仓库入口

- 本仓负责 Wails App、原生桥接、网络控制和 `frontend/` 中的 App 界面；控制台 Web 源码归属 `soha-web`，服务端协议以 `soha-contracts` 为源。
- 在 OpenSoha 多仓工作区中读取 `../AGENTS.md` 一次；独立克隆时使用本仓规则，不要求初始化相邻仓库或规划工具。
- 按任务读取相关原生实现或前端组件；构建与平台打包参考 [Taskfile](Taskfile.yml)、[CI](.github/workflows/ci.yml) 和 [发布流程](.github/workflows/release.yml)，不创建空仓库技能。
- Go 行为改动验证受影响包，主入口为 `GOWORK=off go test ./...`；桌面测试所需的前端产物和平台依赖按 CI 准备。
- 前端检查在 `frontend/` 执行，按改动选择 `npm run typecheck`、`npm run lint`、`npm test`、`npm run build`。局部样式不自动触发原生打包。
- 原生构建使用 `wails3 task build`；平台打包、安装、更新和发布变更按对应 CI/发布任务验收。编译通过不代表原生网络、权限、安装或真实设备验收通过。
- 保留认证、凭据保护、原生权限和网络资源清理边界；不手改生成 bindings 或构建产物。
- 文档和技能改动只检查内容、链接与差异；相关代码和环境未变化时复用成功验证，保留用户未提交改动。
