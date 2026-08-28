# Soha App

Independent Wails 3 desktop client for connecting to a Soha Server. The App owns its React/Vite frontend, exposes native desktop and software-management endpoints under `/app/v1`, and forwards only `/api/v1` requests to the configured server.

## Prerequisites

- Go 1.26.5
- Node.js 22 and npm 10+
- Wails CLI pinned to `v3.0.0-beta.2`

```sh
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.2
npm ci --prefix frontend
```

## Development

Start a local Soha server on `127.0.0.1:8080`, then run:

```sh
wails3 task dev
```

The Vite development proxy and packaged App default to `http://127.0.0.1:8080`. Set `VITE_API_PROXY_TARGET` for frontend-only development. `SOHA_SERVER_URL` is an optional read-only host override; otherwise the server can be changed in App settings.

```sh
SOHA_SERVER_URL=https://soha.example.com wails3 build
```

The production build compiles `frontend/` and embeds `frontend/dist`. It does not read or build `soha-web`.

## Verification

```sh
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
GOWORK=off go test . ./build/...
GOWORK=off go vet . ./build/...
wails3 build
```

## CI Artifacts

The CI workflow is configured to build a Linux `.deb`, a Windows per-user NSIS installer, and a macOS `.app`/`.dmg`. Each uploaded artifact includes a platform `SHA256SUMS-*.txt` manifest generated and verified before upload. These short-lived artifacts are unsigned (macOS uses ad-hoc signing) and are engineering evidence only. Distribution still requires platform signing, notarization where applicable, and installation smoke tests.

## Updates

Update checks use the Wails updater and are disabled unless a release repository is configured. Releases must include platform assets and a `checksums.txt` SHA-256 sidecar.

```sh
SOHA_APP_UPDATE_REPOSITORY=opensoha/soha-app wails3 build
```

Configured builds check shortly after launch and every six hours. Users can also open Settings and run a manual check. `SOHA_APP_UPDATE_TOKEN` is supported for private repositories and must be supplied at runtime, not embedded in distributed builds.

## Software Library

The app reads approved packages uploaded from the Soha internal workbench. Catalog and download requests use the current in-memory login token, and the native runtime verifies the package before opening the system installer.

For local development, a JSON catalog can override the server catalog. Copy `configs/software-catalog.example.json`, replace the sample metadata, and point the app to the resulting file:

```sh
SOHA_APP_SOFTWARE_CATALOG=/etc/soha/software-catalog.json wails3 dev
```

Catalog entries may contain multiple `artifacts`; the app only returns the artifact matching the current Go `platform` and `arch`. Each artifact requires an HTTPS URL, exact byte size, SHA-256 digest, and safe file name. The browser receives only display metadata and a software ID. After confirmation, the native runtime downloads and verifies the package, then opens it with the operating system installer. It does not run a silent privileged installation.

`softwareCatalog` remains the catalog boundary; the server catalog is the default and the JSON adapter is only an explicit override.

## Mobile Preview

Mobile support remains experimental and is outside the desktop foundation release. The generated tasks are smoke-test entry points only:

```sh
wails3 task android:run
wails3 task ios:run
```

Android requires API 35, build-tools 35, NDK 26.3, and a JDK. iOS requires macOS and full Xcode. VPN, enrollment, secure native token storage, and store packaging are outside this first slice.
