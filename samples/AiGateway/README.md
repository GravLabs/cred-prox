# E13 — AI provider gateway

The most common reason to want a credential proxy today: internal apps call an AI
provider API all day, and none of them should hold the provider key. CredProx sits in
front: each app authenticates with **its own caller API key**, CredProx injects the
**real provider key** (`StaticKey` in a header), enforces **per-caller operation
allow-lists**, **throttles** the provider cluster, and **audits** every call. All of it
is plain config — no vendor-specific C#.

## What it shows

- **Caller keys** (`CredProx:Callers`): `chat-app` and `ops-app` each authenticate with
  their own `X-CredProx-Key`; the key is stored only as a SHA-256 hash.
- **The injected provider key** (`CredProx:Credentials:ai-provider`): `StaticKey`,
  `Location: Header`, `Name: Authorization`, `Prefix: "Bearer "`, value from
  `secret:ai-provider-key`. Apps never see it; the inbound caller key is stripped by
  header hygiene and never forwarded.
- **Per-caller operation allow-list**: `chat-app` may only `POST /ai/v1/chat/**` and
  `/ai/v1/messages/**`; anything else (files, admin) answers
  `403 credprox.operation_not_allowed` before anything reaches the provider. `ops-app`
  has no allow-list and may call everything.
- **Per-caller budgets** (`CredProx:Callers:batch-app:Limits`, M15 plan §3.7):
  `batch-app` gets 2 requests/minute across all its keys; the third answers
  `429 credprox.caller_throttled` with `Retry-After` — before the cluster limiter, so
  it never spends a provider permit — and the other callers keep their full budget.
  One chatty app cannot exhaust the shared provider for everyone else.
- **Cluster throttling** (`CredProx:Throttling:Clusters:ai`): 2 permits/second, no
  queue — a burst against the provider gets `429 credprox.throttled`. The two limits
  are independent: the budget protects the other callers from one app, the cluster
  limit protects the provider from all of them.
- **SSE streaming**: the provider's streaming endpoint (`/v1/messages`) passes through
  unbuffered — the smoke proves it by timing the two events the stub flushes 400 ms
  apart. SSE bodies are still credential-scanned: the scrubber runs per event (M22),
  so each event is checked as it arrives instead of waiting on the next one.
- **Response scrubbing** (M20, plan §8.2): the stub echoes the `Authorization` header
  it received — the way error pages and echo endpoints reflect credentials. The caller
  never sees the provider key in any response body: it arrives as `[redacted]`. The
  stub's 200-vs-401 check is the proof the real key still reached the provider.
- **Audit**: one record per call with caller id, route, status — never any key value.

## Run the smoke (CI, no Docker)

```bash
dotnet run -- --smoke
```

The provider is stubbed in-process: every stub endpoint refuses requests that don't
carry the injected key (the check a real provider makes), and the streaming endpoint
writes its two SSE events with a 400 ms gap, flushing as it goes. The smoke asserts:
keyless → 401; chat call → 200 (the stub validated the injected key) **and** the
response shows the stub's echo as `Bearer [redacted]`, never the key itself; first
SSE event arrives < 300 ms after the request (the per-event scrubber must not hold it
back — buffering would push it past the 400 ms gap); chat caller on `/ai/v1/files` →
403; ops caller → 200 (echo also scrubbed); burst of 6 → ≥1 × 429; `batch-app` third
call → `429 credprox.caller_throttled` with `Retry-After` while `chat-app` still gets
200 (per-app isolation); audit shows `proxied_call` per caller, `rejected_call` for the
blocked one, and no log line contains the provider key.

## Point it at a real provider

1. Put the real key in your secret source under `ai-provider-key` (env var or
   `CredProx:Secrets:ai-provider-key` — never committed).
2. Point the cluster at the provider:
   `ReverseProxy:Clusters:ai:Destinations:ai:Address = https://api.openai.com/`
   (OpenAI-style: keep `Authorization` + `Bearer `).
   For Anthropic-style, set the credential to `Name: "x-api-key"` with no `Prefix`,
   add the provider's version header via a route transform
   `{ "RequestHeaderValue": "anthropic-version", "Set": "2023-06-01" }`, and point the
   address at `https://api.anthropic.com/`.
3. Keep the `PathRemovePrefix: /ai` transform or drop it and mount the route at
   `/{**catch-all}` — the provider path is whatever follows the prefix.
4. Call `POST /ai/v1/chat/completions` with a caller key — the provider answers as the
   company account; the app never held the key.

## What just happened (one request traced)

`POST /ai/v1/chat/completions` with `X-CredProx-Key: <chat-app key>` → caller
authentication resolves `chat-app` from the key hash → the operation allow-list admits
`POST /ai/v1/chat/**` → the destination template resolves the cluster → the caller
budget admits or 429s (`chat-app` declares none) → header hygiene strips the caller
key → the `StaticKey` credential attaches `Authorization: Bearer sk-…` (and records it
for the response scrubber) → the cluster limiter hands out a permit (or 429s) → the
settled response passes the response pipeline, where the scrubber removes the injected
value from anything the provider reflects back → the response streams while the audit
sink records `caller=chat-app route=ai status=200 bytes=…`.
