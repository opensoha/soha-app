# Soha App

Independent Wails 3 desktop client for connecting to a Soha Server. The App owns its React/Vite frontend, exposes native desktop and software-management endpoints under `/app/v1`, and forwards only `/api/v1` requests to the configured server.

## Prerequisites

- Go 1.26.6
- Node.js 22 and npm 10+
- Wails CLI pinned to `v3.0.0-beta.16`

```sh
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.16
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

## Desktop UI conventions

- Utility pages keep their route heading accessible but do not repeat a visible title and description when the sidebar and primary control already establish context.
- Mutually exclusive connection modes use a prominent centered segmented control; the primary connection action is one large centered circular button, with its dependent selector directly below.
- IP, gateway, and DNS are shown only from native link readback. Missing values use `-`; a saved preference never implies a successful connection.

## Verification

```sh
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
GOWORK=off go test ./...
GOWORK=off go vet ./...
wails3 build
```

## CI Artifacts

The CI workflow is configured to build a Linux `.deb`, a Windows machine-wide NSIS installer, and a macOS `.app`/`.dmg`. The Windows package includes the privileged `SohaNetworkService`; an unconfigured service is registered as manual and stopped. Each uploaded artifact includes a platform `SHA256SUMS-*.txt` manifest generated and verified before upload. These short-lived artifacts are unsigned (macOS uses ad-hoc signing) and are engineering evidence only. Distribution still requires platform signing, notarization where applicable, and real-device installation smoke tests.

## Updates

On AppArmor-enabled Linux systems, the package loads `/etc/apparmor.d/soha-app` for `/usr/local/bin/soha-app`, allowing WebKitGTK to create its sandbox user namespaces. The profile is unloaded when the package is removed.

Ordinary development builds use update mode `disabled`. Signed release builds inject the runtime version, update mode, and Ed25519 public key with linker flags. A configured build checks 30 seconds after launch and every six hours; checks only update status and never download, install, or restart automatically. A user must click the update action.

- Windows amd64 opens the signed installer release so the App and machine service update as one unit.
- macOS arm64 replaces the complete signed and notarized `.app` from the release ZIP.
- Linux amd64 only opens the fixed GitHub Release page and never replaces the installed package.

The signed manifest is always named `update-manifest-v1.json`, with its base64 Ed25519 signature in `update-manifest-v1.json.sig`. Production builds only use `opensoha/soha-app` GitHub Release assets. Test builds may override `SOHA_APP_UPDATE_MANIFEST_URL`, but only with HTTPS or loopback HTTP.

The release workflow creates a draft, signs platform binaries and the Windows service, signs the manifest, uploads all fixed-name assets, downloads them again, and publishes only after checksum, Authenticode, code-signing, and notarization checks pass. A stable tag must match the version in the Wails, package, and frontend metadata. Production publishing requires these GitHub Actions secrets:

- `SOHA_UPDATE_ED25519_PRIVATE_KEY_BASE64` and `SOHA_UPDATE_ED25519_PUBLIC_KEY_BASE64`
- `SOHA_WINDOWS_CERTIFICATE_PFX_BASE64` and `SOHA_WINDOWS_CERTIFICATE_PASSWORD`
- `SOHA_MACOS_CERTIFICATE_P12_BASE64`, `SOHA_MACOS_CERTIFICATE_PASSWORD`, and `SOHA_MACOS_SIGNING_IDENTITY`
- `SOHA_MACOS_NOTARY_KEY_P8_BASE64`, `SOHA_MACOS_NOTARY_KEY_ID`, and `SOHA_MACOS_NOTARY_ISSUER_ID`

The Ed25519 values are base64 encodings of a raw 32-byte public key and a raw 32-byte seed or 64-byte private key. The private key is decoded only into the runner temporary directory and is never uploaded.

For an internal update-feed smoke, configure the separate `SOHA_TEST_UPDATE_ED25519_PRIVATE_KEY_BASE64` and `SOHA_TEST_UPDATE_ED25519_PUBLIC_KEY_BASE64` secrets and run `app-release` manually. The run produces a private Actions `release-bundle`; it does not create or publish a GitHub Release. Serve that bundle locally and launch the installed test build with:

```sh
SOHA_APP_UPDATE_MANIFEST_URL=http://127.0.0.1:8088/update-manifest-v1.json /path/to/soha-app
```

Windows test builds report the installer release as an external update; they never replace only the desktop executable.

## Windows Endpoint Network Service

The machine-wide installer includes `soha-app-service.exe`, which owns the endpoint WireGuard private key, split routes, DNS, lease renewal, optional mihomo reconciliation, and fail-closed cleanup. The desktop App can only query, connect, or disconnect through `\\.\pipe\OpenSoha.Soha.NetworkService`; the pipe ACL admits LocalSystem, Administrators, and the exact configured user SID. Enrollment tokens, TLS keys, WireGuard keys, and managed mihomo subscription URLs never cross that IPC boundary, and the service replaces inherited ACLs on secret files with a LocalSystem/Administrators-only DACL before reading them. For ZTNA connections, the signed-in renderer requests a five-minute one-time access grant and passes it once through the protected pipe; the token is never persisted, logged, or returned in endpoint status.

Install WireGuard for Windows first. Provision `%ProgramData%\OpenSoha\Soha\service.json`, its CA/client certificate files, and the one-time enrollment token as administrator or through MDM. [`configs/windows-network-service.example.json`](configs/windows-network-service.example.json) documents the strict configuration shape. The control certificate URI SAN must be `spiffe://opensoha.local/network-control/endpoint/<runtimeId>`; ingest uses a separate certificate with `spiffe://opensoha.local/network-ingest/endpoint/<runtimeId>`.

For managed mihomo, run mihomo separately with its external controller bound to the exact loopback URL in `service.json`, and place the matching controller secret in the protected state directory. The service advertises the `mihomo` capability only when both values are valid. Soha applies a proxy-only configuration: mihomo does not own TUN, the default route, system DNS, or WireGuard routes. `app_subscription` remains user-selected and observable; Soha does not treat it as an authorization boundary.

After provisioning, rerun the installed service binary with `install`. It validates the whole configuration, switches `SohaNetworkService` to delayed automatic start, and starts it. Endpoint private keys and WireGuard `.conf.dpapi` state remain under the protected state directory and are DPAPI-bound to LocalSystem. Endpoint routes provide reachability only: the gateway's deny-first firewall remains the authorization boundary and a broad `NetworkLease` cannot override `ProtectedSet`. Removing the App unregisters the service but intentionally preserves `%ProgramData%\OpenSoha\Soha` for administrator-controlled recovery or removal.

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

Android requires API 35, build-tools 35, NDK 26.3, and a JDK. iOS requires macOS and full Xcode. Mobile VPN, enrollment, secure native token storage, and store packaging remain outside this first slice.
