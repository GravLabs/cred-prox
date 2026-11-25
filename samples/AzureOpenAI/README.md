# Azure OpenAI gateway (keyless)

Callers reach an Azure OpenAI deployment through CredProx. CredProx authenticates to Azure with a
short-lived **Microsoft Entra token** — the deployment's managed identity, or your `az login`
session locally — and **there is no API key anywhere**: not in config, not in an environment
variable, not in the caller's request. Each caller's own key admits it, and its operation rules
name the deployments it may use.

## What it shows

- **`TokenCredential` outbound auth**: `Type: "TokenCredential"` with only a `Scope`
  (`https://cognitiveservices.azure.com/.default`) — the token itself comes from the ambient Azure
  identity the host passes to `AddAzure(...)` (cited: the Azure OpenAI REST reference lists the
  Entra scope; the Entra how-to shows `DefaultAzureCredential` picking up `az login` locally and
  the managed identity on Azure; fetched 2026-11-24). A role such as **Cognitive Services OpenAI
  User** on the resource is what authorizes inference calls (cited: same how-to).
- **Per-caller deployment allow-lists**: Azure OpenAI puts the deployment in the path
  (`/openai/deployments/<name>/chat/completions?api-version=...`, cited: the Azure OpenAI REST
  reference, fetched 2026-11-24), so a per-caller `Paths` rule naming one deployment pattern is
  exactly a deployment allow-list. In this config `chat-app` may use `gpt-4o` only; `admin-app`
  has no `Operations` list and may use every deployment.
- **No API key, and it stays that way**: the upstream credential carries `Authorization: Bearer
  <entra-token>`; the `api-key` header exists nowhere. The offline stand-in refuses a request
  without a bearer **and** refuses one that carries `api-key`, mirroring the keyless intent of an
  Entra-only setup (the live refusal behaviour of a key-disabled resource is UNVERIFIED here —
  offline milestone, no live run).
- **Token metering**: the route opts into the `openai` usage format; Azure's documented response
  carries the same `usage` object (`prompt_tokens` / `completion_tokens` / `total_tokens`, cited:
  the chat REST reference, fetched 2026-11-24), so the M54 metering attributes tokens per caller.

## Run it

The offline shape needs no Azure account and makes no billable call:

```bash
cd samples/AzureOpenAI
./smoke.sh        # runs the offline cells: stand-in Azure OpenAI + real fail-closed startup
```

The stand-in (`StubApi/`) answers `POST /openai/deployments/<name>/chat/completions` only with a
bearer token, refuses `api-key`, and returns a canned completion with a `usage` object.

## Point it at a real resource

1. Give the host's identity a role on the resource (e.g. **Cognitive Services OpenAI User** —
   cited: the Entra how-to) — a user-assigned managed identity, or your own `az login` for a local
   run.
2. Replace `YOUR-RESOURCE` in `Destinations`/`Clusters` with your resource name
   (`https://<name>.openai.azure.com`).
3. Call it:

```bash
curl -sS http://localhost:5108/aoai/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01 \
  -H "X-CredProx-Key: azureopenai-demo-chat-key-1" \
  -H "content-type: application/json" \
  -d '{"messages":[{"role":"user","content":"ping"}]}'
```

`chat-app`'s key answers for the demo. The caller's `X-CredProx-Key` never reaches Azure — the
pipeline replaces upstream auth with the Entra token, and the scrubber keeps what it injected out
of any echo. How a live Azure OpenAI resource answers in detail (rate limits, exact error bodies)
is **UNVERIFIED** here; the wire shape above is cited from Microsoft's reference pages.

## Live run (lead-only)
`bash scripts/live-run.sh azureopenai` is the real thing. Without `CREDPROX_M52_BILLABLE=1`
in `live.env` it creates nothing and skips the chat; with the go-ahead it creates and
destroys its OWN resource (`scripts/live-m52-aoai.sh`): a dedicated resource group, a
kind-`OpenAI` account with local (key) auth disabled, one chat deployment at the
SKU tier `live.env` names, capacity 1, and "Cognitive Services OpenAI User" for the
signed-in `az` principal at the
account scope — torn down again on every exit path, with read-backs. Only names come from
`live.env` (`AZURE_OPENAI_LOCATION`, `AZURE_OPENAI_MODEL`, `AZURE_OPENAI_MODEL_VERSION`,
`AZURE_OPENAI_SKU`, `AZURE_OPENAI_DEPLOYMENT_SKU`): the endpoint and deployment the live cell dials are the ones the run
created, exported by the runner. The story and gates are in `docs/live-testing.md`; the
live chat has not been executed yet.

## Verify it

`./smoke.sh` runs the `Sample=AzureOpenAI` cells plus the stamp cell. The cells prove: startup
binds this config through the real fail-closed path; a caller outside its deployment allow-list is
refused `403` before the stand-in sees anything; `chat-app` gets its completion and `usage` is
counted; the stand-in's two refusals (no bearer, api-key present) pin what "keyless" means on the
wire; and the Entra token — canned in the offline run — arrives as `Authorization: Bearer`, never
as `api-key`.

## What just happened (one request traced)

1. `chat-app` POSTs to `/aoai/openai/deployments/gpt-4o/chat/completions` with its
   `X-CredProx-Key`.
2. CredProx admits the caller by key hash, matches its Operations rule (one deployment pattern),
   and forwards to the cluster.
3. The pipeline asks the `TokenCredential` for a token at scope
   `https://cognitiveservices.azure.com/.default` (cached per caller partition) and attaches
   `Authorization: Bearer <token>`.
4. The answer streams back; metering reads `usage` and counts tokens to `chat-app` — no key value
   exists anywhere on the way.
