# Soha App

Wails 3 host for the standalone Soha desktop client. It shares authentication and API clients with `soha-web`, but uses its own desktop routes for home, applications, software, account, and settings. Only `/api/v1` requests are forwarded to the configured Soha server.

## Prerequisites

- Go 1.26.5
- Node.js and the `soha-web` dependencies
- Wails CLI pinned to `v3.0.0-beta.2`

```sh
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.2
npm install --prefix ../soha-web
```

## Development

Start a local Soha server on `127.0.0.1:8080`, then run:

```sh
wails3 dev
```

The Vite development proxy uses `VITE_API_PROXY_TARGET`. Packaged applications use `SOHA_SERVER_URL`; both default to `http://127.0.0.1:8080`.

```sh
SOHA_SERVER_URL=https://soha.example.com wails3 build
```

The frontend source remains in `../soha-web`. `npm run build:app` stages its output into `frontend/dist` for embedding.

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

Wails 3 mobile support is experimental. The generated tasks are the current smoke-test entry points:

```sh
wails3 task android:run
wails3 task ios:run
```

Android requires API 35, build-tools 35, NDK 26.3, and a JDK. iOS requires macOS and full Xcode. VPN, enrollment, secure native token storage, and store packaging are outside this first slice.
