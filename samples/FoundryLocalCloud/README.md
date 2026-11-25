# FoundryLocalCloud: local plus cloud, one front

**This sample has no failover and no fallback.** It runs one CredProx front in front of
two model routes: a local Foundry Local server on loopback and a cloud Anthropic route.
Which route a request takes is decided twice and only by configuration — the URL the
caller puts in its request, and the caller's own Operations allow-list. If the local
model is down, the local call fails right there; nothing retries it on the cloud, and
nothing ever moves traffic between the routes behind your back. (The word "fallback"
describes a different design; this is not it.)

Routing by config alone looks like this: the local route (`/gateway/**`) carries no
upstream credential — a Foundry Local server on `127.0.0.1` authenticates nothing, so
whatever fronts it is the only gate — while the cloud route (`/cloud/**`) attaches a
`StaticKey` credential (`CredProx.Credential` metadata) that no app ever holds. Every
caller may take the local route; only callers whose allow-list names the cloud route can
reach it. In the shipped config `local-app` names only the local route and `dual-app`
names both — that difference is the entire mechanism.

Token metering works per route too: each route names its usage format
(`CredProx.Metering.Usage: openai` on the local route, `anthropic` on the cloud route),
so one meter carries both vendors' token counts, tagged with the caller. Like the
FoundryLocalGateway sample: a streamed OpenAI-format call is metered only when the
caller sends `stream_options.include_usage`, because CredProx never rewrites request
bodies.

## Run it offline (stub upstreams)

```bash
dotnet run --project samples/FoundryLocalCloud --environment Development
```

`StubApi/` answers both arms on loopback (local shape on 8103, Anthropic shape behind a
demo key on 8104). With `Metrics__Console=true` the CredProx meter prints to the console:

```bash
curl -sS http://localhost:5106/gateway/v1/chat/completions \
  -H 'X-CredProx-Key: credprox-demo-key-local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-4b-generic-cpu:3","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true}}'
```

`local-app` answering on the local route and `403` from the cloud route
(`/cloud/v1/messages`), while `credprox-demo-key-dual` answers on both, is the whole
demo. The demo keys and the demo cloud key are throwaway values committed on purpose;
replace them and the cloud key in `appsettings.json` (or a secret source) before any
real use.

## Run it for real

Set the Development override aside and point the cloud destination at a real Anthropic
endpoint with a real key in the `CredProx:Secrets:anthropic-cloud-key` secret — the
cloud leg then costs real money per call and the caller-key gate is still the only
thing in front of it. The cloud route sets `anthropic-version: 2023-06-01` on the
forwarded request itself (`RequestHeader`/`Set` transform in `appsettings.json`), so
callers do not need to send it — without it Anthropic answers `400 anthropic-version:
header is required` for every request. Keep the local destination on loopback: the
Foundry Local port must stay reachable only from this host, because it authenticates
nothing.

`./smoke.sh` runs the offline cells (both routes' happy paths, the allow-list refusal
proven before the cloud stand-in is touched, the 401, the metering line for both
formats, the config-differential witness showing the 403 dies exactly when the
allow-list entry does, and the stand-in's own version-then-key refusals driven direct
past the gateway).
