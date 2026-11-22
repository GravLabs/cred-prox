# Azure Container Apps: the deployment host

This is the app you actually deploy to Azure Container Apps: callers knock with an
API key, the vendor credential arrives from Key Vault, and reaching the vault itself
needs no secret — the Container App's **managed identity** does that. No modes and no
harness in here; every fact is config or environment. The live-gate harness (one image,
four roles, its own in-image smoke) lives in `tools/aca-live-harness`; it is not this
host's concern.

## What it shows

- **Managed identity → Key Vault → `secret:` refs** (`appsettings.json` + 8 lines of
  Program.cs): with `KeyVault__Uri` set, the stock Azure Key Vault configuration
  provider plugs in over `DefaultAzureCredential` — under Container Apps that resolves
  to the app's user-assigned identity through the platform's env contract, no
  connection string anywhere. A vault secret `CredProx--Secrets--acme-vendor-key`
  answers `secret:acme-vendor-key`; the caller-key hash is held as a secret ref too.
  `ReloadInterval` is set explicitly because the provider default (null) never polls a
  rotated value.
- **Caller keys at the internal ingress** (`CredProx:CallerAuth`, `CredProx:Callers`):
  `X-API-Key` validated against SHA-256 hashes, constant-time compare; missing and
  wrong keys get the identical refusal.
- **The vendor key no app ever holds** (`CredProx:Credentials:acme`): a `StaticKey`
  header credential — the proxy injects `Authorization: Bearer <key>`; the stand-in
  echoes what it received and CredProx's response scrubber redacts it before the
  caller sees it.
- **Probes without credentials** (`/health`): Container Apps liveness/readiness hit a
  plain health endpoint; nothing authenticates or forwards there.
- **`secret:` refs with no vault** (`KeyVault__Uri` unset): the same references resolve
  from plain config (env/user-secrets) exactly like every other sample — that is the
  path the offline run and the offline check use. The Key Vault + managed identity path
  is the same stock provider the shipped MicrosoftGraph sample runs, and the live-gate
  harness (`tools/aca-live-harness`) proves it against a real vault, reload included.

## Run it (offline, no Azure)

```bash
cd samples/AzureContainerApps
(cd StubApi && dotnet run &)   # the vendor stand-in
dotnet run
```

Then call through the gateway:

```bash
curl -s http://localhost:5097/acme/thing \
  -H 'X-API-Key: credprox-e17-aca-demo-key'
```

```
{"result":{"item":"acme-widget"},"saw_authorization":"Bearer [redacted]"}
```

Nobody sent the vendor key: the gateway took it from config (the inline demo value —
with no vault set the `secret:` refs fall back to `CredProx:Secrets` like in every
sample), injected it upstream, and redacted the echo.

## Verify it

```bash
cd samples/AzureContainerApps && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=AzureContainerApps
```

The cell runs the host on its bare shipped config: the value the vendor receives is
the configured key as a bearer header, the caller's copy arrives `[redacted]`, and
neither the vendor key nor the caller key appears anywhere in the response body or the
host console. The Key Vault + managed identity path is proven live by
`tools/aca-live-harness`, whose own offline proof covers the provider's reload
mechanism.

## Deploy it to Azure Container Apps

Build the image from the repository root (pack the packages first):

```bash
docker build -f samples/AzureContainerApps/Dockerfile -t credprox-aca:latest .
```

1. **Identity.** Create (or reuse) a user-assigned managed identity and attach it to
   the Container App.
2. **Vault access.** On the key vault, grant that identity **Key Vault Secrets User**.
   Nothing else is needed — the app reads through the identity, not a stored secret.
3. **Secrets.** Set the two vault secrets the config references:
   `CredProx--Secrets--demoCallerKeyHash` → `sha256:<64 hex>` of your real caller key,
   `CredProx--Secrets--acme-vendor-key` → the real vendor key. Rename the config
   entries to fit your callers and vendor — they are plain config keys.
4. **The app.** `az containerapp create` with `--ingress internal` (zero public
   listeners — callers reach the internal FQDN), `--target-port 8080`, `--secrets`
   free (secrets come from the vault, not from app secrets),
   `KeyVault__Uri=https://<your-vault>.vault.azure.net/` in env,
   `AZURE_CLIENT_ID=<the identity's client id>` in env (the `DefaultAzureCredential`
   setting that names the user-assigned identity; **required whenever the app's identity
   is user-assigned** — unset, the credential reaches for the system-assigned identity
   the app does not have, so it cannot read the vault and the app never serves a
   request), **and**
   `--args --urls http://+:8080`. The args part is not optional: the shipped
   `appsettings.json` `Urls` pin (`http://localhost:5097`, for the offline run)
   beats the `ASPNETCORE_URLS` the image bakes — verified empirically on a real
   deploy 2026-11-22 — so only the start arg moves the bind to the target port.
5. **Probes.** Point liveness and readiness at `/health` (plain 200, GET, no
   credential).
6. **Call it** from inside the VPC: `curl https://<internal-fqdn>/acme/thing -H
   'X-API-Key: <your caller key>'`.

## What just happened (one request traced)

`GET /acme/thing` with `X-API-Key: <caller key>` → caller authentication resolves the
caller from the SHA-256 hash store (a secret ref answered by the vault) → the `acme`
credential hands over the cached vendor key (on a cache miss: read from the vault
through the managed identity) → placement injects `Authorization: Bearer <key>` and
registers the value with the response scrubber → the vendor answers; its echo of the
key arrives to the caller as `Bearer [redacted]` → the host console shows the call with
no credential value in sight (the offline cell proves exactly that).
