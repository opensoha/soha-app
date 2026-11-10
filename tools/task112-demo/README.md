# Soha App Task112 演示

本机模拟后台绑定 `127.0.0.1:18112`。桌面包由 Task122 App 候选 `09f2fddb` 分出的专用工作树构建，使用 `task112-demo` 命名配置和独立 macOS bundle ID。后台不占用现有 Soha 端口或数据库，演示状态保存在进程内。

登录账号 `demo`，密码 `task112-demo-only`，服务地址由启动器设为 `http://127.0.0.1:18112`。

| 页面 | 可以体验 |
| --- | --- |
| 应用门户 | SQL 平台、盘古系统、商城管理后台。可收藏，点击卡片进入对应的本机登录演示 |
| 网络连接 | 切换 Wi-Fi／有线，查看本机链路信息 |
| VPN | 自动或手动选择模拟接入点，查看延迟与连接状态 |
| 代理 | 开启和关闭 Mihomo，切换演示节点，查看采样速率、累计流量和连接数 |

门户跳转为一次性本机演示回执。网络和代理调用通过带专用构建标签的 App 转到本机模拟后台，系统网卡、代理、TUN 和原生网络服务维持原状态。

桌面构建需要与候选版本匹配的前端依赖和干净的 Task122 Contracts checkout（`8f2c35e8`）。在本目录设置 `TASK112_CONTRACTS_DIR` 指向该 checkout，再运行 `opensoha-verify run -- bash build.sh`。运行 `python3 launch.py` 启动后台及桌面包，运行 `python3 launch.py --stop` 停止。

在 App 仓库根目录构建浏览器预览，然后启动独立的 `127.0.0.1:18113` 服务。

```sh
cd frontend
opensoha-verify run -- npm run build -- --outDir ../tools/task112-demo/runtime/browser-dist
cd ../tools/task112-demo
python3 -B browser.py
```

进程状态、日志和产物位于 `runtime/`。后台重启后演示连接、流量、收藏和登录令牌重置，命名 App 配置保留。
