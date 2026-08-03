# Soha App

Wails 3 host for the Soha desktop and experimental mobile client. Phase 1 reuses the login and application shell from the sibling `soha-web` repository and forwards only `/api/v1` requests to a configured Soha server.

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

## Mobile Preview

Wails 3 mobile support is experimental. The generated tasks are the current smoke-test entry points:

```sh
wails3 task android:run
wails3 task ios:run
```

Android requires API 35, build-tools 35, NDK 26.3, and a JDK. iOS requires macOS and full Xcode. VPN, enrollment, secure native token storage, and store packaging are outside this first slice.
