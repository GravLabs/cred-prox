# FoundryLocalAgent: the agent pattern on a local model

The M53 AgentTokens pattern — an agent whose tools are HTTP calls gated by CredProx,
with the caller's named operations as the tool boundary — running its conversation on a
local model: a Foundry Local server on loopback, speaking the OpenAI chat format, metered
through the route's `openai` usage format. A live run costs nothing per call. It is a
sibling of AgentTokens rather than a mode inside it: that sample's fixtures and README
are one Entra story end to end, and mixing two model contracts into one host would blur
what each sample pins (ADR-0009 prescribes separate samples).

The offline stand-in (`StubApi/`) replays what a local thinking model actually sends,
measured in `docs/foundry-local-notes.md` — and that is where the three differences
from a cloud demo live:

- **Empty content beside `reasoning_content` is not a failure.** A thinking model
  often answers a tool turn with no content at all plus a `reasoning_content` block;
  the signal is the tool call or the next turn. The agent notes the reasoning and
  keeps going — cells drive exactly this shape.
- **Budget for the reasoning.** The agent asks for 800 completion tokens: a small
  budget truncates the reasoning and the call degrades in ways the caller can't see.
- **CPU-speed timeouts.** The default per-call timeout is 120 s and the smoke runner
  gives the whole loop two minutes; a local model on CPU is not a cloud endpoint.

The gate story is unchanged from AgentTokens because it is the same machinery: the agent
holds its **own Entra token** — no key of the gateway's exists in its process, and it can
see none. CredProx validates the token against the `CallerToken` authority, maps its
client id (`azp`) through `TokenClientIds` to the caller entry, and admits exactly the
named operations the token's `roles` claim names. A well-formed token from a client the
config never lists gets 401 and moves nothing. When the model asks for `admin_reset` — a
tool no admitted rule covers — CredProx answers 403 before the tool server sees the
request, the agent hands the refusal back as a readable tool error, and the model answers
around it: a dead tool is a fact in the conversation, not a crash.

## Run it offline

```bash
./smoke.sh
```

That is the whole offline world: the stand-in also acts as the OIDC issuer
(`openid-configuration` plus a `/jwks` listing the run's throwaway key's PUBLIC half),
the host validates tokens through its real OIDC pipeline against it — `RequireHttpsMetadata`
is off for the offline issuer alone, because it is http on loopback — and the cells mint
short-lived caller tokens with the fixture's private key, the same test-token approach the
AgentTokens smokes use. Nothing in the sample is a real credential. To see the halves
separately:

```bash
dotnet run --project samples/FoundryLocalAgent/StubApi                          # stand-in + issuer
ASPNETCORE_ENVIRONMENT=Development dotnet run --project samples/FoundryLocalAgent  # the gate, offline config
```

The gate then answers an unauthenticated model call with 401; the agent itself needs a
token the stub issuer would sign — the smoke fixture mints one per cell, so drive the
full loop through `./smoke.sh`. The agent prints its turns on stdout (`[reasoning]`,
`[tool name -> ok]`, `[answer] …`); the gate prints audit records and meters on its
console. Env knobs: `GatewayUrl`, `Model`, `TimeoutSeconds`; token source: `AGENT_TOKEN`
(offline) or `AGENT_TENANT_ID` / `AGENT_CLIENT_ID` / `AGENT_CLIENT_SECRET` /
`AGENT_API_SCOPE` (the live Entra grant).

## Run it for real

Set the Development override aside: the model route then points at your Foundry Local
server (`127.0.0.1:5273` by default — keep it reachable only from this host, it
authenticates nothing), the tools route at your real tool service, and
`CallerToken:Authority` / `Audience` at your Entra tenant and your agent-API client id;
list the agent app's client id under `TokenClientIds` and name its operations. The agent
then fetches its own Entra token with the client-credentials grant — the same live path
AgentTokens proves: a mapped app is admitted, an unmapped one gets 401, now on a local
model that costs nothing per call.
