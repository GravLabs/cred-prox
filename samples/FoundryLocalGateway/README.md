# Local AI gateway (Foundry Local)

A Foundry Local server runs on your own machine and its endpoint authenticates
nothing — whatever can reach the port can spend your model with no record of who. So
CredProx in front of it is the only gate the deployment has: caller API keys
authenticate every request, per-caller operation allow-lists decide what each app may
call, and the OpenAI usage blocks come back as per-caller token counts. Foundry Local
stays bound to 127.0.0.1, which means only CredProx on the same host can reach it at
all — the caller-facing surface is CredProx's port, and it is the one that knows names.

**Start here (offline):** `./smoke.sh` runs the sample's smoke cells against the
StubApi stand-in (no model, no network). **Against a real Foundry Local:**
`foundrylocal serve` listens on `http://127.0.0.1:5273` and the shipped
`appsettings.json` already points there — `dotnet run` and call the gateway.

## A streamed call

```bash
curl -N http://localhost:5105/gateway/v1/chat/completions \
  -H "X-CredProx-Key: credprox-demo-key-alpha" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3-4b-generic-cpu:3","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hello"}]}'
```

Ask for `stream_options.include_usage` or the token counts never arrive: the measured
Foundry Local stream carries usage only in a final usage-only SSE event (`choices: []`
beside `usage`), and that event appears only for requests that asked for it. Without
it the call is still fully metered — requests and bytes per caller — just without
token counts. The non-streaming answer carries the usage block inline, so it needs no
such request.

## What it shows

- **A route with no upstream credential at all.** The route carries no
  `CredProx.Credential` metadata — there is nothing to attach — and the startup
  validators accept that: a missing credential key is the opt-out, not an error. The
  caller key is the only authentication anywhere on the path.
- **Caller keys and allow-lists as pure config.** `chat-app` may POST
  `/gateway/v1/chat/**` and nothing else; `ops-app` names no Operations, so it may
  call everything. Wrong key is a 401, right key outside the allow-list is a 403,
  both before a byte reaches the model.
- **Per-route usage metering in the OpenAI format.** The route names
  `"CredProx.Metering.Usage": "openai"`, so the built-in readers count both answer
  shapes: the inline `usage` object on a JSON completion and the usage-only event on
  an `include_usage` stream.
- **The measured vendor shape, offline.** `StubApi/` replays what the real loopback
  build does — no auth, usage rules as above, and a 405 for `GET /v1/models`, which
  the real build answers exactly that way.

The demo keys (`credprox-demo-key-alpha` = `chat-app`, `credprox-demo-key-beta` =
`ops-app`) are throwaway and public on purpose; your real caller keys go to your
secret source.
