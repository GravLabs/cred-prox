# Live testing (on demand, local only)

Live tests run a sample host **as shipped** against the real vendor, from your own
machine, when you choose to. They never run in CI and never run with a plain
`dotnet test CredProx.slnx` — the project `tests/CredProx.LiveTests` is kept out of
the solution the same way the vendor stub projects are, and guard cells in
`CredProx.Tests` fail CI if that ever changes. Run evidence lands in
`docs/live-validation-report.md` when a run happens.

## One command

```bash
./scripts/live-run.sh githubapp
./scripts/live-run.sh aigateway
./scripts/live-run.sh graph
./scripts/live-run.sh agenttokens
./scripts/live-run.sh aca
```

Exit codes: **PASS 0**, **FAIL 1**, **SKIP or refused 2**. A run is vendor-scoped:
running one vendor never executes the other vendor's live cell, so filling one
vendor's file can never spend or touch the other — and it is doubly enforced
inside the cells: `scripts/live-run.sh` exports `CREDPROX_LIVE_VENDOR` for its
own leg only, and every live attribute requires it to name its own vendor, so a
plain `dotnet test` of the live project skips every live cell even when the env
file or leftover scratch is present. An aigateway run still starts the
GitHubApp sample against its local stand-in for the shared offline legs; that makes no
GitHub traffic. The graph run carries a real lifecycle: `scripts/live-graph-app.sh`
creates one Entra app registration (plus its service principal and one 30-day
secret, held only in a mode-600 scratch file), the run uses it, and destroy deletes
it again on every exit path — the destroy's read-back (zero apps, zero service
principals) decides whether the run may PASS. The agenttokens run mirrors that
discipline with `scripts/live-agenttokens-app.sh`: three app registrations (one
resource app carrying an `api://` identifier and two application roles,
`docs-read` and `model-call`, both assigned to both client apps, whose 30-day
secrets are piped straight into the mode-600 scratch handoff), and the same
destroy read-back over all three names plus zero leftover app-role values
gating the PASS. The agenttokens and foundrylocal runs share this one lifecycle
script and scratch, so they never run at the same time: create refuses while the
scratch's `resource-audience.txt` handoff already exists, and destroy removes
the scratch. The aca
run drives `scripts/live-m46-aca.sh` end to end: apply creates the resource set
(resource group, Key Vault, two user-assigned identities, container apps environment,
registry) and resolves every role id from the API at run time, material writes the
run's three vault secrets from mode-600 scratch files only, push builds and pushes
three images with docker and reads back each pushed digest, deploy attaches the
identities before applying each spec and refuses on any identity or digest read-back
mismatch, verify starts one acacheck job whose C-lines decide, and destroy deletes
everything back to the resource group on every exit path with poll-to-gone read-backs.
Its live leg is script-driven — the app serves internal ingress only, so no test
process can reach it (disclosed; the offline proofs are canned-az and a loopback cell).
The azureopenai run creates and destroys its OWN resource (the standing-resource
form was removed on 2026-11-24 at the owner's choice): under the go-ahead flag,
`scripts/live-m52-aoai.sh` creates a dedicated resource group, an Azure OpenAI
account with local (key) auth disabled, one small chat deployment, and grants
"Cognitive Services OpenAI User" to the signed-in `az` principal at the account
scope; the runner polls the created endpoint until the role is live — bounded,
with the deadline printed — then exports the run's endpoint and deployment to
the test process, and on every exit path destroys the group again with
read-backs (group gone; the soft-deleted account purged and its absence read
back from the soft-deleted list — the read-back, not the verb's exit, is the
verdict; role assignments zero — an unresolvable scope prints
SKIPPED, explicitly NOT a confirmed zero, rather than claim a zero it never
measured). A run only ever touches a resource group it created itself: the
fixed group name must be FREE — if it already exists, `create` refuses before
any write and names how to clear it, and `destroy` deletes only the group its
own scratch recorded, never the fixed name as a guess (no recorded group means
a SKIPPED group read-back and a non-zero exit, not a sweep). If a group of
that name is a leftover from an earlier run whose handoff was lost, the owner
confirms by hand that it holds only `credprox-m52` resources and deletes it
themselves; the script never deletes a group it did not create. Only names come
from `live.env` — location, model, model version, account SKU,
deployment SKU; the run mints the account name `credprox-m52-<6 hex>` itself, because the
account name and its DNS subdomain are global namespaces. The zero-billable run
needs neither `az` nor `curl`: the create, the authenticated role-wait probe
and both those gates belong to the armed leg, and the single tiny chat spends
only under `CREDPROX_M52_BILLABLE=1`.
Every outward step (create, destroy,
deploy) is a lead action; build seats prove only the offline legs. The PASS line names what was
observed — for githubapp the exchange count, cache hits and the two forwarded
calls and their 200s; for aigateway the forwarded models call, its 200 and the two
refusal statuses; for graph the two credential styles' Graph statuses; for
agenttokens the mapped caller's 200 and the unconfigured client's 401 (plus the
real agent round-trip when the billable opt-in is on); for aca the
acacheck pass count and the job status; for azureopenai the caller's 200 on the
admitted deployment with its usage counts, and the 403 on the deployment its rule
does not admit — and never
contains an App id, installation id, token, caller key, repository name, or tenant
or subscription id.

## Secrets: one central file, mode 600

Every live vendor reads ONE machine-local file: `~/.config/credprox-live/live.env`,
mode **exactly 600** (the runner refuses any other mode). Flat `KEY=VALUE` lines,
`#` comments. Variable names only — never commit this file, never paste it anywhere:

| Variable | Vendor(s) | What it is |
|---|---|---|
| `APP_ID` | githubapp | your GitHub App's numeric App id |
| `INSTALLATION_ID` | githubapp | numeric installation id of the App on your org/repos |
| `PRIVATE_KEY_BASE64` | githubapp | the App's private-key PEM, base64 on one line |
| `ANTHROPIC_API_KEY` | aigateway, agenttokens, foundrylocal | an Anthropic API key (starts with `sk-ant-`) |
| `CREDPROX_M53_BILLABLE` | agenttokens | set to `1` to run the billable agent cell; absent or any other value skips it |
| `CREDPROX_M54_BILLABLE` | foundrylocal | set to `1` to run the billable cloud-leg cell (one tiny Anthropic messages call through the local-plus-cloud sample); absent or any other value skips it |
| `TENANT_ID` | graph, agenttokens, foundrylocal, aca | your Entra tenant id (a GUID) — one value, shared |
| `FOUNDRY_LOCAL_MODEL` | foundrylocal | OPTIONAL: the model id the run must use. The preflight validates it with one tiny chat before anything is created and exports exactly it to the live cell; absent, the default comes from the sample's own appsettings (`FoundryLocal:Model`) and is validated the same way |
| `AZURE_OPENAI_LOCATION` | azureopenai | the Azure region the run creates its one-run resource in (e.g. `swedencentral`) — a name, not a secret |
| `AZURE_OPENAI_MODEL` | azureopenai | the chat model the run deploys (e.g. `gpt-4o`) |
| `AZURE_OPENAI_MODEL_VERSION` | azureopenai | the exact model version to deploy (e.g. `2024-11-20`) |
| `AZURE_OPENAI_SKU` | azureopenai | the account SKU the run creates (e.g. `s0`) |
| `AZURE_OPENAI_DEPLOYMENT_SKU` | azureopenai | the deployment SKU tier the run requests for its chat deployment (e.g. `Standard`; the tier choice and its trade-off are in `docs/azureopenai-notes.md`) |
| `CREDPROX_M52_BILLABLE` | azureopenai | set to `1` to arm the whole billable run: create the resource, spend one tiny chat through it, destroy it again; absent or any other value creates nothing and skips the chat |
| `CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS` | azureopenai | OPTIONAL: how long the armed run waits for its role assignment to go live on the created endpoint (default 300); must be a positive whole number of seconds or the run refuses |
| `CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS` | azureopenai | OPTIONAL: how long destroy polls the soft-deleted list for the run's account name to go absent (default 300); must be a positive whole number of seconds or destroy refuses before issuing any write |

A file holding only some vendors' variables is normal, not an error: each run
SKIPs listing its own missing names and says nothing about the rest. Vendor
isolation stays: a vendor's run sees only its own variables — another vendor's
line in this file never reaches its test process. The only exceptions are the
opt-in billable extras: agenttokens children receive `ANTHROPIC_API_KEY` and
`CREDPROX_M53_BILLABLE` as well when set, and foundrylocal children receive
`CREDPROX_M54_BILLABLE` and `ANTHROPIC_API_KEY` — but only together and only
when `CREDPROX_M54_BILLABLE=1`, so a stray key can never arm a billable call;
azureopenai armed runs hand their children `CREDPROX_M52_BILLABLE` plus the endpoint
and deployment THE RUN CREATED (runner-exported from the scratch handoff) — a stray
`AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_DEPLOYMENT` sitting in the file is simply
ignored, the standing-resource form is gone —
and the runner's leak scan
covers the loaded values of every secret variable present, whoever put it there.
Old per-vendor files are no longer read; if one still sits beside the central
file, the runner names it once and says it is ignored, never echoing its content.

The one command that fills the file (hidden prompts; Enter keeps a value as it is):

```bash
./scripts/live-credentials.sh           # fills or updates live.env, mode 600
./scripts/live-credentials.sh status    # names, set/unset, mode — never values
```

The GitHub App private key is taken as a PEM file path and stored base64 on one
line; the Anthropic key is asked for with `read -rsp`, so it shows on no command
line and stays out of your shell history; `TENANT_ID` can be read from your
(read-only) az sign-in instead of typed. A tenant id is not a secret, but it
follows the same file discipline, and the graph run's client id and secret, the
agenttokens run's apps and secrets, and the aca run's vault material are NOT in
this file — each run creates them and deletes them again. The agenttokens billable
leg, on the other hand, reads its API key and its opt-in flag from this file like
every other live variable.

Or build the file by hand — the `umask` makes it owner-only as it is created,
`read -rsp` hides the key, and the final `chmod` is explicit:

```bash
umask 077
mkdir -p ~/.config/credprox-live
read -rsp 'Anthropic API key: ' key; echo
{
  printf 'APP_ID=%s\n' '<your-app-id>'
  printf 'INSTALLATION_ID=%s\n' '<your-installation-id>'
  printf 'PRIVATE_KEY_BASE64=%s\n' "$(base64 -w0 /path/to/private-key.pem)"
  printf 'ANTHROPIC_API_KEY=%s\n' "$key"
  printf 'TENANT_ID=%s\n' "$(az account show --query homeTenantId -o tsv)"
} > ~/.config/credprox-live/live.env
unset key
chmod 600 ~/.config/credprox-live/live.env
```

Drop the lines for vendors you do not run; the file may hold any subset. The Entra/Azure
vendors (graph, agenttokens, foundrylocal, aca) also need the az CLI on PATH and signed in
(`az login`) — both gates are read-only; the sign-in is what the secretless
credential style rides. An aca run additionally needs the az `containerapp`
extension — its gate dies before any write verb — and docker on PATH for the push
step, which runs after apply.

## Outcomes

| Outcome | When | Exit |
|---|---|---|
| PASS | every check for that vendor below held against the real vendor | 0 |
| FAIL | a check failed, or secret material appeared in the run log (the kind is named, the content never is) | 1 |
| SKIP / refused | env file missing or a variable missing (each name listed), or mode is not exactly 600 (the actual octal is named); for the Azure vendors (graph, agenttokens, foundrylocal, aca) also when the az CLI is absent or not signed in — both checked before anything is created; for the armed azureopenai leg also when az is absent, not signed in, or curl is missing (the zero-billable azureopenai run needs none of them); for foundrylocal also when no loopback model server answers, or the selected model id answers no tiny chat (SKIP names the id and the http code; nothing is created) | 2 |

Values are read exactly as written, with no quote stripping. A value with the wrong shape (a quoted
key, a key that is not base64) is not a SKIP: the live cell checks it and FAILs, naming which
variable is wrong, never its content.
The secret wait is an outcome source too: if a run-created client secret never mints a token within
CREDPROX_M46_SECRET_WAIT_SECONDS (default 120, polled every 5 s with a 15 s cap per poll), the run
FAILs before the live cell starts — and the armed destroys still run, so nothing created is left
behind by the timeout.
The role wait is a second outcome source of the same shape: Entra lands a fresh
app-role assignment into issued tokens only after a delay, so an agenttokens run
waits for the mapped token to carry BOTH app roles (docs-read and model-call) and
FAILs before the live cell starts — armed destroys still running — when it never
does within CREDPROX_M46_ROLE_WAIT_SECONDS (default 300, polled every 5 s with a
15 s cap per poll; a run can overshoot that budget by about 20 s).

## What a GitHubApp PASS proves

- CredProx minted the app JWT and made **exactly one** exchange for an installation
  token at GitHub (counted inside the host by its own `CredProx` meter, observed by
  the startup-hook witness — no test double sits on this path).
- Two real API calls (`GET /github/installation/repositories`) were forwarded and
  GitHub answered **200** to both, as the installation (`Server: github*` asserted).
- The second call was served from the cached token — no second exchange.
- The captured host log and test output contain none of the loaded secret material
  and no token/JWT shapes (a scanner runs over both, in-test and in the runner).

Everything the live test does against GitHub is read-only.

## What an AiGateway PASS proves

- The shipped AiGateway sample, pointed at `https://api.anthropic.com/` by
  configuration only (the README's Anthropic-style recipe: the key sent as
  `x-api-key` with no prefix, `anthropic-version` via a route transform), answered
  a caller-authenticated `GET /ai/v1/models` with a real **200** — the caller held
  only its own caller key, never the provider key.
- An unknown caller key was refused with **401** and an operation outside the
  caller's allow-list with **403**, both as CredProx's own problem document — and
  the 403 carried no Anthropic `request-id` header, so the request never left the
  machine.
- **A PASS run makes zero billable calls.** The only upstream call is the models
  list (`GET /v1/models`, no tokens); the messages POST is refused at the proxy.
- The captured host log and every caller-visible body contain none of the loaded
  key material and no `sk-ant-` shape (the scanner runs in-test and in the runner).

## What a MicrosoftGraph PASS proves

- The shipped MicrosoftGraph sample, with ONLY the overrides its README names
  (`TokenEndpoint`, `ClientId` and the secret via the CredProx secrets key for the
  OAuth style; `ASPNETCORE_ENVIRONMENT` alone for the secretless style), reached
  real Microsoft Graph with **both** credential styles: the client-credentials
  style via `GET /graph/v1.0/users?$top=1` (an application token carries no
  signed-in user for `/me`), answered **403** with a Graph `request-id` header.
  The caller sees it the way CredProx shows every vendor error: a
  `credprox.vendor_error` problem document with the status kept and Graph's own
  error embedded in `extensions.vendor_detail`, whose code is
  `Authorization_RequestDenied`. That is Graph's own refusal, which means the tenant
  issued a real app-only token and CredProx attached it: Graph accepted it as a
  token and refused it for holding no permission. The same check proves vendor
  error normalisation against a real vendor. And the Azure CLI identity
  style via `GET /graph/v1.0/me`, answered **200**.
  What is NOT proven here is an app-token 200: that would need admin consent,
  which this run deliberately does not take.
- The client id and secret the first style used belonged to an app registration
  this run created and deleted again before the runner exits; the app held **no**
  application permission and no admin consent — that absence is the proof the run
  needs. One 30-day client secret was piped straight to the scratch handoff, never
  printed; the destroy read-back — zero app registrations, zero service principals,
  scratch dir removed — is what lets the run PASS, and any leftover fails it.
- The destination stays exactly as shipped (`graph.microsoft.com`); the captured
  run log and caller-visible bodies contain neither the run-created client secret
  nor any `eyJ` JWT shape (the scanner runs in-test and in the runner).
- Cost per run: nothing billable. Entra app registrations and their password
  credentials carry no charge, and the run creates nothing in any resource group.

## What an AgentTokens PASS proves
- The shipped AgentTokens sample, with only the overrides its README names
  (`Authority` for the run's tenant, `Audience` — the API's own client id, the
  form Entra's v2 access tokens carry — and the mapped client's id in the
  caller's `TokenClientIds`), accepted a **real Entra-issued app token** for the
  run-registered API with **200** and forwarded the request stripped: CredProx
  removes the caller's `Authorization` header after authenticating, and the
  stand-in upstream confirmed the caller's `Bearer` token never arrived.
- A second real token — same tenant, the same `docs-read` and `model-call` app
  roles, but minted by a client that is NOT a configured caller — was refused with **401** as CredProx's
  own `credprox.caller_unauthenticated` problem document, and the stand-in's
  request counter did not move: the refusal is CredProx's decision before any
  upstream was touched, not a vendor artifact.
- Disclosed deviation: the shipped destination is the `docs.example.com`
  placeholder, so the run repoints it (and only it) at a loopback stand-in. The
  destination is not the thing under proof; the token validation and caller
  mapping are. The stand-in never echoes the `Authorization` value it receives.
- The three app registrations (resource app with its exposed identifier
  `api://<its own app id>` and its `docs-read` and `model-call` application roles,
  mapped and unmapped client apps, both roles assigned to both) and both 30-day
  client secrets
  belonged to this run; the secrets and that identifier were piped straight to
  the mode-600 scratch handoff and never printed. The identifier takes the
  app-id form because a tenant's default protection policy refuses a fixed
  `api://` name at create; the live cell reads the audience from the handoff.
  The destroy
  read-back — zero app registrations, zero service principals and zero app-role
  values under all three display names, scratch removed — is what lets the run
  PASS, and any leftover fails it.
- The captured run log and caller-visible bodies contain neither minted client
  secret nor any `eyJ` JWT shape (the scanner runs in-test and in the runner).
- Cost per run: nothing billable by default. Entra app registrations and their
  password credentials carry no charge, and the run creates nothing in any resource
  group.
- Billable opt-in: with `CREDPROX_M53_BILLABLE=1` and an Anthropic key loaded (the
  Secrets table above), one cell runs the shipped agent for real against the vendor
  — cheapest model, small token budget, fixed short prompt, a few cents. Without
  the opt-in that cell skips with a stated reason; it never fails for being absent.
## What an AzureContainerApps PASS proves

- The shipped AzureContainerApps sample ran **as shipped** — two containers in one
  app (the CredProx proxy and the shipped stand-in vendor), internal ingress only —
  on a Consumption container apps environment, pulling both images from the run's
  own registry with the kubelet identity.
- The proxy read its vendor credential from Key Vault through its user-assigned
  managed identity: the app spec carries secret references only; the value never
  appears in the spec, the log, or argv.
- C1: `GET /health` answered **200** unauthenticated. C2: a call carrying a valid
  caller key reached the stand-in vendor and answered **200**, and the body showed
  the vendor `Authorization` as `Bearer [redacted]` — the caller key did not reach
  the vendor, and the vendor key never reached the caller. C3: the same call with no
  caller key was refused **401** by the proxy. All three ran inside the cluster as an
  acacheck job; the job reaching `Succeeded` with 3/3 is the gate, and a start that
  returns no name is resolved from the job's execution list, never by re-starting.
- The deploy read-backs decide before verify runs: app identity type
  `UserAssigned`, image-pull identity on, two identities attached, and the running
  container stamped with the digest the push step read back — any mismatch refuses
  the run.
- Everything is deleted before the runner exits, on the failure path too, and the
  deletion is read back: resource group polled to gone, Key Vault **PURGED** (purge
  protection is omitted, not disabled), registry and both identities gone, role
  assignments zero, scratch removed — any survivor fails the run.
- Disclosures. The live leg is script-driven and internal-only: no test process
  reaches the app from outside; the offline proofs are canned-az read-back cells and
  a loopback cell that runs the same three checks against the shipped host and
  stand-in on localhost. The two containers share a pod, so the proxy reaches the
  stand-in at localhost (stated in the app template header). And deploy passes
  `--urls` as a container arg because the shipped `appsettings` `Urls` setting beats
  the `ASPNETCORE_URLS` value baked in the image (verified empirically).
- Cost per run: the SKUs are the smallest available — a standard Key Vault, a Basic
  registry, Consumption execution for app and job — and the resource set lives for
  minutes; after destroy nothing bills. A what-if plan of the resource set
  (`infra/azure/credprox-m46-aca-sub.bicep`) is available before apply; like every
  other live step, running it is a lead action.

## Proving the scaffold without any secrets

The offline legs of `tests/CredProx.LiveTests` always run (Layer=Offline): the
witness counts exactly one exchange and one cache hit against the local stand-in,
the AiGateway cell shows the provider key reaching its stand-in while the caller
sees only `Bearer [redacted]` and both refusals leaving the stand-in's call count
untouched, the leak scanner bites on planted fake secret material (including a
lone `gho_` and a lone `sk-ant-` value), and the env-file contract (missing names,
mode refusal, 600 round-trip, value-shape problems) is pinned for all five vendors.
The Entra vendors' lifecycle scripts are pinned too, against a canned `az` stub on
PATH: the destroy read-back flips its own exit code when the canned lists still
show leftovers (app registrations and service principals for both vendors, plus
leftover app-role values for agenttokens), create
pipes the run-created secrets to the mode-600 scratch handoff without echoing them
anywhere, the create-side read-backs fail loudly when the canned API output shows
no `api://` identifier, an app-role set that is not exactly `docs-read` plus
`model-call` (the canned values arrive in reversed order, so a positional compare
cannot pass by luck), or no role assignment on a client SP, the agenttokens cells
also prove the three apps stay three distinct principals end to end, the signed-in and no-az
gates die before any write verb, and `--dry-run` prints the plan without calling
a write verb. The aca script carries the same proof depth: its sign-in and extension
gates die before any write verb, vault secrets are passed only as `--file` arguments
with the minted values asserted absent from stdout, stderr and the log, every pushed
digest is read back from the registry rather than trusted, the deploy
identity/pull/stamp read-backs are asserted to flip the exit code, a verify start
that returns no name consults the execution list exactly once, and destroy's
read-backs — purge state, zero role assignments, resource group gone — each have
their own leftover cell. The acacheck trio is additionally pinned offline by a
loopback cell that execs the shipped host, the shipped stand-in and the harness's
acacheck mode on localhost.
The live cells skip loudly when an env file is absent and the runner turns that
into exit 2.
