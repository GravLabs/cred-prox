# AI provider gateway

The most common reason to want a credential proxy today: internal apps call an AI
provider API all day, and none of them should hold the provider key. CredProx sits in
front: each app authenticates with **its own caller API key**, CredProx injects the
**real provider key** (`StaticKey` in a header), enforces **per-caller operation
allow-lists**, **throttles** the provider cluster, and **audits** every call. All of it
is plain config — no vendor-specific C#.

## What it shows

- **Caller keys** (`CredProx:Callers`): `chat-app`, `ops-app` and `batch-app` each
  authenticate with their own `X-CredProx-Key`; the key is stored only as a SHA-256 hash.
- **The injected provider key** (`CredProx:Credentials:ai-provider`): `StaticKey`,
  `Location: Header`, `Name: Authorization`, `Prefix: "Bearer "`, value from
  `secret:ai-provider-key`. Apps never see it; the inbound caller key is stripped by
  header hygiene and never forwarded.
- **Per-caller operation allow-list**: `chat-app` may only `POST /ai/v1/chat/**` and
  `/ai/v1/messages/**`; anything else (files, admin) answers
  `403 credprox.operation_not_allowed` before anything reaches the provider. `ops-app`
  has no allow-list and may call everything.
- **Per-caller budgets** (`CredProx:Callers:batch-app:Limits`): `batch-app` gets 2
  requests/minute across all its keys; the third answers `429 credprox.caller_throttled`
  with `Retry-After` — before the cluster limiter, so it never spends a provider permit —
  and the other callers keep their full budget. One chatty app cannot exhaust the shared
  provider for everyone else.
- **Cluster throttling** (`CredProx:Throttling:Clusters:ai`): 2 permits/second, no
  queue — a burst against the provider gets `429`. The two limits are independent: the
  budget protects the other callers from one app, the cluster limit protects the
  provider from all of them.
- **SSE streaming**: the provider's streaming endpoint (`/v1/messages`) passes through
  unbuffered — the cells prove it by timing the two events the stand-in flushes 400 ms
  apart. SSE bodies are still credential-scanned: the scrubber runs per event, so each
  event is checked as it arrives instead of waiting on the next one.
- **Response scrubbing**: the stand-in echoes the `Authorization` header it received —
  the way error pages and echo endpoints reflect credentials. The caller never sees the
  provider key in any response body or SSE event: it arrives as `[redacted]`. The
  stand-in's 200-vs-401 check is the proof the real key still reached the provider.
- **Audit**: one record per call with caller id, route, status — never any key value.
- **Usage metering** (`CredProx:Metering`): a request counter and request/response byte
  histograms on the `CredProx` meter, tagged by caller, credential, destination, route and
  status class — configuration names only, never a key. Exported over OTLP by default;
  `Metrics:Console` prints them to stdout instead. The `ai` route opts into token counting
  by naming its usage format (`CredProx.Metering.Usage: "anthropic"`): token counters come
  from the provider's own usage report, so a stand-in that reports no usage stays
  unmetered for tokens.

## Run it

```bash
cd samples/AiGateway
(cd StubApi && dotnet run &)   # the provider stand-in
ASPNETCORE_ENVIRONMENT=Development dotnet run   # offline: appsettings.Development.json repoints both endpoints at the stub
```

Then call through the gateway with a caller key and no provider key of your own:

```bash
curl -s -X POST http://localhost:5088/ai/v1/chat/completions \
  -H 'X-CredProx-Key: a1c7e94b2d8f4705b6e3a9c1d4f802e7' \
  -H 'Content-Type: application/json' \
  -d '{"model":"demo"}'
```

```
{"result":{"object":"chat.completion"},"stub_saw_authorization":"Bearer [redacted]"}
```

The provider saw `Authorization: Bearer <provider key>` on the call; you see it
redacted — the response scrubber removes every injected value from anything the
provider reflects back.

To watch the metering leg instead of exporting OTLP, run the gateway with the console
exporter and call it again:

```bash
Metrics__Console=true OTEL_METRIC_EXPORT_INTERVAL=2000 \
  ASPNETCORE_ENVIRONMENT=Development dotnet run
```

The stdout shows `credprox.requests`, `credprox.request.bytes` and
`credprox.response.bytes` carrying `credprox.caller: chat-app` and the route tag —
counts you can point at an OTLP collector by dropping the `Metrics__Console` override.

## Point it at a real provider

1. Put the real key in your secret source under `ai-provider-key` (env var or
   `CredProx:Secrets:ai-provider-key` — never committed).
2. Point the cluster at the provider:
   `ReverseProxy:Clusters:ai:Destinations:ai:Address = https://api.openai.com/`
   (OpenAI-style: keep `Authorization` + `Bearer `).
   For Anthropic-style, set the credential to `Name: "x-api-key"` with no `Prefix`,
   add the provider's version header via a route transform
   `{ "RequestHeader": "anthropic-version", "Set": "2023-06-01" }`, and point the
   address at `https://api.anthropic.com/`.
3. Keep the `PathRemovePrefix: /ai` transform or drop it and mount the route at
   `/{**catch-all}` — the provider path is whatever follows the prefix.
4. Call `POST /ai/v1/chat/completions` with a caller key — the provider answers as the
   company account; the app never held the key.

## Verify it

```bash
cd samples/AiGateway && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=AiGateway
```

Eight cells against the provider stand-in: keyless → 401 with the provider's hit
counter unmoved; chat call → 200 (the stand-in validated the injected key) **and** the
echo arrives as `Bearer [redacted]`, never the key itself; the first SSE event lands
< 300 ms after the request with the second a full provider delay later (nothing
buffered) and the key redacted inside the stream; chat caller on `/ai/v1/files` →
`403 credprox.operation_not_allowed` while the ops caller passes; burst of 6 against
2 permits/s → ≥1 × 429; `batch-app`'s third call → `429 credprox.caller_throttled` with
`Retry-After` while `chat-app` still gets 200 (per-app isolation); a metered chat call →
the console exporter prints `credprox.requests` with `credprox.caller: chat-app` and no
key value; and the audit log
shows `proxied_call` per caller, `rejected_call` for the blocked one, and no key value
anywhere.

## What just happened (one request traced)

`POST /ai/v1/chat/completions` with `X-CredProx-Key: <chat-app key>` → caller
authentication resolves `chat-app` from the key hash → the operation allow-list admits
`POST /ai/v1/chat/**` → the destination template resolves the cluster → the caller
budget admits or 429s (`chat-app` declares none) → header hygiene strips the caller
key → the `StaticKey` credential attaches `Authorization: Bearer <provider key>` (and
records it for the response scrubber) → the cluster limiter hands out a permit (or
429s) → the settled response passes the response pipeline, where the scrubber removes
the injected value from anything the provider reflects back → the response streams
while the audit sink records `caller=chat-app route=ai status=200 bytes=…`.
