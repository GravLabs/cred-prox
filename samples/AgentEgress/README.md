# AI agent egress

"Never give the agent the key" is the security principle vendors now push, and agents
running MCP tools or plain HTTP calls are the fastest-growing consumers of third-party
APIs. This sample is that shape end to end: an agent runtime calls Salesforce through
CredProx with **only its own caller API key**. The OAuth client secret — and the session
token CredProx mints from it — never appear anywhere the agent can read. All of it is
plain config; the Salesforce integration is vendor facts, not vendor C#.

## What it shows

- **Per-agent caller keys** (`CredProx:Callers`): `crm-agent` and `support-agent` each
  authenticate with their own `X-CredProx-Key`, stored only as SHA-256 hashes. The agent
  process holds nothing else — no client id/secret, no session token, no refresh logic.
- **Per-agent tool boundaries** (`Operations`): the allow-list *is* the tool surface.
  `crm-agent` may only `GET /salesforce/services/data/**` (its MCP tool is "query");
  `support-agent` may only `POST .../sobjects/Case` (its tool is "open a case"). Any
  other call answers `403 credprox.operation_not_allowed` before anything reaches the
  vendor — an agent cannot be prompt-injected into a tool it does not have.
- **The Salesforce credential shape** (`CredProx:Credentials:salesforce`):
  `OAuthClientCredentials`, `ClientAuthentication: FormPost` (client_id + client_secret
  as form-body parameters — Salesforce's spelling), client secret via
  `secret:sf-client-secret`, `Scope: api`.
- **One shared credential, one cached token**: both agents ride the same `salesforce`
  credential; the token cache means exactly one issuance at the token endpoint no matter
  how many agents call (the cells count issuances). Each agent still gets its own key,
  its own tool allow-list, and its own audit identity.
- **The session token never reaches the agent**: the stand-in's data API echoes the
  `Authorization` header it validated into a `debug_authorization` field — the same
  thing a real error page or verbose endpoint does. The response scrubber removes the
  injected session token there: the agent sees
  `"debug_authorization":"Bearer [redacted]"`. The value is also absent from every log
  line; the audit records caller, route, status — never a credential.

## Run it

```bash
cd samples/AgentEgress
(cd StubApi && dotnet run &)   # the vendor stand-in
ASPNETCORE_ENVIRONMENT=Development dotnet run   # offline: appsettings.Development.json repoints both endpoints at the stub
```

Then call through the gateway as the CRM agent — with only its own key:

```bash
curl -s http://localhost:5089/salesforce/services/data/v62.0/query?q=SELECT+1 \
  -H 'X-CredProx-Key: credprox-e15-crm-agent-demo-key'
```

```
{"result":{"records":[{"attributes":{"type":"Account"},"Id":"001xx000003DWYl","Name":"Acme"}],"totalSize":1,"done":true},"debug_authorization":"Bearer [redacted]"}
```

The vendor saw its issued bearer on the call and returned real data; the agent sees the
record with the session token redacted — it never held, and cannot recover, either half
of the credential chain.

## The production shape: an MCP server as the agent runtime

The cells play the agent's role with `HttpClient`. In production the agent runtime is
one hop away and holds exactly one secret — its CredProx key. With the Model Context
Protocol SDK the tool handler is roughly:

```csharp
// In the MCP server process. The only credential here is the agent's CredProx key,
// from its own environment — never the vendor's.
var http = new HttpClient { BaseAddress = new Uri("https://credprox.internal/") };
http.DefaultRequestHeaders.Add("X-CredProx-Key", Environment.GetEnvironmentVariable("CREDPROX_KEY")!);

tools.AddTool("crm_query", "Run a SOQL read against the CRM", async (QueryInput q) =>
{
    // CredProx attaches the Salesforce session token, enforces this agent's
    // allow-list, and scrubs the token from whatever the vendor echoes back.
    var response = await http.GetAsync(
        $"/salesforce/services/data/v62.0/query?q={Uri.EscapeDataString(q.Soql)}");
    return await response.Content.ReadAsStringAsync();
});
```

Deployment reads as three trust zones: the **agent** holds only its caller key;
**CredProx** (this host, any web farm) holds the vendor facts in its config and secret
sources and is the only place the OAuth exchange happens; the **vendor** sees one
service identity with an auditable caller id per agent on every request.

## Point it at real Salesforce

1. Put the connected app's values in your secret source: `sf-client-secret`, and set
   `ClientId` to the connected app's consumer key.
2. Point the config at your org:
   - `CredProx:Credentials:salesforce:TokenEndpoint` →
     `https://login.salesforce.com/services/oauth2/token` (or your My Domain login host)
   - `ReverseProxy:Clusters:salesforce:Destinations:salesforce:Address` →
     `https://<your-instance>.salesforce.com/`
3. Keep `ClientAuthentication: FormPost` — that is Salesforce's client-auth spelling.
4. Call `GET /salesforce/services/data/v62.0/query?q=...` with an agent key. CredProx
   mints and caches the session token, the scrubber keeps it out of the responses, and
   revoking an agent is deleting one entry under `CredProx:Callers`.

For per-**user** Salesforce tokens (the agent acting as a person), the same route works
with `TokenExchange` instead of `OAuthClientCredentials` — the caller key admits the
agent, and the exchanged token is cached per user.

## Verify it

```bash
cd samples/AgentEgress && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=AgentEgress
```

Four cells against the stand-in: keyless and forged keys → 401 with the token endpoint
untouched; the CRM agent's read → 200 with the record echoed, the debug field redacted,
and exactly one issuance; the tool boundaries — CRM on Case →
`403 credprox.operation_not_allowed`, support on query → 403, support's create → 200
(echo redacted) and **still one issuance** across both agents (the shared cache); and
the audit log from the host's own console — `proxied_call` and `rejected_call` per
agent, no line containing the client secret, the session token, or any agent's own key.

## What just happened (one request traced)

`GET /salesforce/services/data/v62.0/query?q=...` with `X-CredProx-Key: <crm-agent key>`
→ caller authentication resolves `crm-agent` from the key hash → the operation
allow-list admits `GET /salesforce/services/data/**` (anything else, 403 first) →
header hygiene strips the caller key → the `salesforce` credential hands over a cached
session token (minted once via the form-posted client credentials; on a 401 it is
refreshed and re-attached transparently) and registers the value with the response
scrubber → Salesforce answers; the `Authorization` value it echoes is replaced with
`[redacted]` before the response reaches the agent → the audit sink records
`caller=crm-agent route=salesforce status=200` with no credential in sight.
