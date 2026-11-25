# Azure OpenAI wire-shape notes (M52)

Measured findings behind `samples/AzureOpenAI`, each cited to Microsoft's own pages. Anything not
verifiable offline stays in the Unverified section.

## 1. Request URL shape

Cited: [Azure OpenAI reference](https://learn.microsoft.com/en-us/azure/ai-foundry/openai/reference)
(fetched 2026-11-24):

```http
POST https://YOUR_RESOURCE_NAME.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT_NAME/chat/completions?api-version=2024-06-01
```

`api-version` is a query parameter with a `YYYY-MM-DD` structure; the deployment is named in the
path — which is what makes a per-caller path rule a deployment allow-list.

## 2. Authentication: two documented styles, this sample uses Entra

Same reference (fetched 2026-11-24): API-key auth sends the key in the `api-key` HTTP header;
**Microsoft Entra ID auth** puts the token in the `Authorization` header as `Bearer YOUR_AUTH_TOKEN`.

Cited: [Entra how-to](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/managed-identity)
(page updated 2026-08-04, fetched 2026-11-24): a short-lived access token for an identity granted a
role on the resource; `DefaultAzureCredential` picks up `az login` on a dev machine and the managed
identity on an Azure host ("Use a user-assigned managed identity" — pass its client ID, or set
`AZURE_CLIENT_ID`); inference roles are **Cognitive Services OpenAI User** or **…Contributor**; the
control plane uses a different audience (`management.azure.com`) and inference roles do not grant
it. The sample uses `DefaultAzureCredential` and the data plane only.

## 3. Token scope for this API shape

Cited: [chat REST reference, Security Requirements](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/chat?view=rest-microsoft-foundry-v1)
(fetched 2026-11-24): OAuth2Auth scope `https://cognitiveservices.azure.com/.default` — the scope
this sample configures. Note the Entra how-to's Python examples for the newer
`https://.../openai/v1/` path use the `https://ai.azure.com/.default` audience; both are
documented, each for its own path shape. This sample pins the deployments path shape, so
`cognitiveservices.azure.com/.default` is the cited scope. Whether a resource accepts either
audience for either path shape in every configuration is UNVERIFIED here.

## 4. Response `usage` fields — the metering claim

Cited: same chat REST reference (fetched 2026-11-24): the chat completion response carries
`usage: { completion_tokens, prompt_tokens, total_tokens }` with optional
`completion_tokens_details` / `prompt_tokens_details`. That is the OpenAI `usage` format the M54
readers (ADR-0009, format `"openai"`) already parse, so metering applies to Azure OpenAI without
new code — the response-shape match was checked against the cited schema, not assumed.

## 5. Azure does not replace OpenAI's JSON

The cited reference's response example is the OpenAI completion object (id/created/choices/usage);
nothing Azure-specific is added to the completion body itself. Error bodies use Azure's own error
envelope — the sample does not parse bodies either way.

## 6. The live leg's control-plane facts (M52 part B)

The create/destroy script carries the full citation header (`scripts/live-m52-aoai.sh`,
docs fetched 2026-11-24); the load-bearing facts, each cited there:

- Account create: `az cognitiveservices account create --kind OpenAI --sku <sku>
  --custom-domain <name> --yes`. A custom subdomain is required for Entra ID
  auth (managed-identity how-to). Local (key) auth is **not** disabled at
  create: the `--api-properties disableLocalAuth=true` composition this note
  once marked DERIVED was **falsified by the first live run** (2026-11-25) —
  `--api-properties` lands on `properties.apiProperties` and leaves
  `properties.disableLocalAuth` unset; the read-back correctly refused the
  account at zero spend. A composition assembled from two separately
  documented halves is a hypothesis until something reads it back. The
  property is set after provisioning with the generic ARM PATCH —
  `az resource update --ids <account id> --set properties.disableLocalAuth=true`
  (az resource reference, documented with the literal `--ids $id
  --set properties.x=y` example form). The disable-local-auth page documents
  the property through Policy, ARM and PowerShell and carries **no Azure CLI
  verb** — the verb above is from the generic resource reference, and that is
  stated rather than papered over. Whether the PATCH settles before the very
  next read is UNVERIFIED; the single read-back is the only decider, and a
  False stops the run before any (billable) deployment create.
  https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth
  https://learn.microsoft.com/en-us/cli/azure/resource
- Deployment: `az cognitiveservices account deployment create ... --model-format
  OpenAI --sku-name "$AZURE_OPENAI_DEPLOYMENT_SKU" --sku-capacity 1`. The tier is a
  live.env name, not a hard-coded constant (the fifth required creation name).
  **Standard vs GlobalStandard:** `--sku-name` accepts `Standard`, `GlobalBatch`,
  `GlobalStandard` and `ProvisionedManaged` (create-resource how-to). `Standard` is
  pay-per-token capacity allocated in the account's own region, where "models
  available in each region and throughput might be limited"; `GlobalStandard`
  routes across any Azure region, is the type Microsoft says to start with for
  general workloads, and carries the highest quota (deployment-types concept
  page). A one-run throwaway deployment has no residency requirement either way,
  and the classic create-resource CLI example uses `Standard` at capacity 1 — so
  `Standard` is the example value live.env ships with, and an owner hitting a
  regional quota wall sets `AZURE_OPENAI_DEPLOYMENT_SKU=GlobalStandard` instead.
  Capacity 1 is the smallest capacity appearing in any Microsoft example; the
  docs state **no numeric minimum** for a Standard deployment (UNVERIFIED
  whether 1 is the floor).
  https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/create-resource
  https://learn.microsoft.com/en-us/azure/foundry-classic/foundry-models/concepts/deployment-types
- Model choice: `AZURE_OPENAI_MODEL` + `AZURE_OPENAI_MODEL_VERSION` must name a
  model version Azure still accepts for a **new** deployment. Live run 3
  (2026-11-25) proved the refusal real: `gpt-4o-mini 2024-07-18` was rejected at
  deployment create with `az error code: ServiceModelDeprecating` — at zero
  spend. The read-only catalog is `az cognitiveservices model list
  -l <location>`: each entry carries `kind` and a nested `model` object with
  `name`, `version` and `lifecycleStatus`. Measured in eastus2 (2026-11-25,
  az 2.91.0): the OpenAI-kind entries show `GenerallyAvailable | Preview |
  Deprecating`, with `gpt-4o-mini 2024-07-18` = `Deprecating` and the
  `2026-03-17` version live.env names today = `GenerallyAvailable`. A
  `Deprecated` status was
  not seen in that region's catalog that day; the create guard refuses that
  name too rather than bet a run on it. `az cognitiveservices usage list
  -l <location>` is the paired quota read. The script's model pre-check runs
  this catalog read before ANY write and refuses a `Deprecating` or
  `Deprecated` pick (witnessed offline against the canned az).
- Reasoning models need the **reasoning request shape**. The GA version
  live.env names today is a reasoning model, and Microsoft's reasoning how-to
  lists `max_tokens` as unsupported for that family — `max_completion_tokens`
  is required — bills reasoning tokens **inside** `max_completion_tokens`, and
  names `reasoning_effort` values `none | minimal | low | medium | high | xhigh | max`.
  A cap that reasoning outgrows still answers HTTP 200 with an incomplete
  status (reason `max_output_tokens`) and possibly EMPTY visible content, and
  the usage line is still present — so the live cell asserts the 200, the
  refused caller's 403 and `usage.total_tokens > 0`, never the content. It
  caps at 2000 tokens and **omits `reasoning_effort` entirely**: which values
  a given model accepts is unverified (newer models may take only a subset of
  the list above), and omission is the one shape every reasoning model is
  known to accept - the cap bounds the cost on its own. The
  response's `completion_tokens_details.reasoning_tokens` is already counted
  inside `completion_tokens`, so the metering reader stays two-field per
  ADR-0009; nothing maps the details object.
  https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/reasoning
- Provisioning read-back polls `properties.provisioningState`; the documented enum is
  `Accepted | Creating | Deleting | Moving | Failed | Succeeded | ResolvingDNS`
  (REST `accounts/get`, api version 2024-10-01) — `Failed`/`Deleting` are treated as
  fatal, the rest keep polling.
- Role: `"Cognitive Services OpenAI User"` granted with `az role assignment create
  --assignee-object-id <id> --assignee-principal-type User --scope <account id>`;
  the id comes from `az ad signed-in-user show --query id`. The docs state
  assignments can take up to five minutes to take effect — a 403 right after
  assignment means wait, not troubleshoot; the runner polls the created endpoint
  authenticated (bounded, printed deadline) before the cell runs.
- Teardown: `az group delete --yes --no-wait` then poll `az group exists` to false.
  Whether a role list over the deleted scope answers `[]` or an error is
  **UNVERIFIED** in the docs, so destroy accepts both zero-shapes (and pins both
  offline).
- Purging the soft-deleted account: `az cognitiveservices account purge
  --location <location> --resource-group <rg> --name <name>` and
  `az cognitiveservices account list-deleted --location <location>` are
  documented GA verbs (az cognitiveservices account reference; the purge
  example names location, resource group and name). A deleted account keeps
  its name reserved until purged; **the docs state no duration** for how long
  a deleted (or freshly purged) name is held — name-retention-duration is
  UNVERIFIED — so what a run verifies is its own purge read-back, never a
  retention window. The purge verb's exit is never the verdict (a never-created
  account makes it error too); the list-deleted read-back decides.
- The purge settles **asynchronously** — how long is UNVERIFIED: the first
  live run observed the name still listed at destroy time and absent from a
  hand re-read about three minutes later (one observation, not a bound). The
  read-back therefore polls, bounded with a printed deadline, and a list read
  that errors for the whole budget is reported as could-not-verify — it fails
  the destroy like a confirmed leftover instead of borrowing the clean
  verdict's exit.
  https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account
- The role-propagation probe polls the **data-plane Models list**: `GET
  {endpoint}/openai/models?api-version=2024-10-21` (REST Models - List, fetched
  2026-11-25) — zero-cost, read-only, and readable by the granted role: the
  **Cognitive Services OpenAI User** definition carries the dataAction
  `Microsoft.CognitiveServices/accounts/OpenAI/*/read`, whose only exclusion is
  stored-completions (Azure built-in role definitions, ai-machine-learning page).
  `2024-10-21` is the **GA release of the data-plane inference specification**
  (Azure OpenAI reference page), and it is the api-version this operation is
  documented under; the reference's chat-route *example* names the older GA
  `2024-06-01` — same specification, earlier release — so probe and sample route
  deliberately do not share a version. The `/openai/v1/models` candidate was
  rejected for a scope reason, not a path reason: §3 notes the v1 paths are
  documented against the `ai.azure.com` audience, while this probe's bearer
  token is minted for `cognitiveservices.azure.com/.default` — the Models list
  sits on the same path family and audience the sample already authenticates to.
  **Live run 4 (2026-11-25) is what chose this probe:** the runner used to poll
  `GET /openai/deployments?api-version=2024-02-01`, and that list verb is not
  part of the current data-plane API — a correctly authorised caller answers 404,
  which the runner (rightly) refused to read as propagation and aborted on. The
  create was fully green and the destroy fully clean that run; nothing billable
  ran. The abort design survived; only the probe target changed. A 200 means the
  role is live, 401/403 keep polling until the bound, and anything else aborts.
  Chat-route audit for the same class of problem, done 2026-11-25 and re-cut
  the same day after a field-vs-release finding: the chat completion verb is
  ALIVE in the GA spec — the reference's own versioning example is
  `POST .../openai/deployments/<deployment>/chat/completions` — but the
  request body carries its own release floor. The live cell sends
  `max_completion_tokens`, which the API version lifecycle guide shows
  arrived in `2024-09-01-preview` (with `max_tokens` unusable on the
  reasoning family); the release the cell first dialed PREDATES the field,
  whose schema that release does not define at all. Whether such a request
  is ignored or refused is not documented anywhere — a refusal landing as a
  400 before spend is the outcome run 5 must not meet — so the cell now
  dials `2024-10-21`, the GA release of the data-plane inference
  specification named by the reference page, through ONE named const
  shared by both of the cell's URLs (pinned offline). The cap and the
  reasoning-family semantics are documented on the CURRENT chat view:
  learn publishes no separately-dated view for `2024-10-21` — asking that
  dated view value renders the v1 page (measured 2026-11-25; an earlier
  cut of this note read that v1 page as a dated view and said so, which
  this cut corrects). What proves the dated release accepts this body is
  the first live run, which dials exactly this version against the real
  resource. The `2024-12-01-preview` floor that circulates for reasoning
  models is the PREVIEW track's `reasoning_effort` addition; this cell
  deliberately sends no effort field, so the GA release carries its body.
  The README's curl carries **no** token-cap field at all (messages-only
  body), so its older GA example version stands. The sample carries **no**
  api-version of its own: `appsettings` names no api-version and the proxy
  forwards the caller's query string unchanged, so the only two pinning
  sites are the README example and the live cell.
  https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle
  (field-addition history) and
  https://learn.microsoft.com/en-us/azure/ai-services/openai/reference
  (names `2024-10-21` as the GA release of the data-plane inference API,
  sentence checked verbatim 2026-11-25). The current chat view is the v1
  page §3 already cites:
  https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/chat?view=rest-microsoft-foundry-v1

## Unverified (the first live run died at the local-auth read-back — nothing billable ran)

- How a **key-disabled** resource answers a request that carries `api-key` (401? ignored header?).
  The offline stand-in refuses it to pin the sample's intent; the live behaviour is UNVERIFIED.
- The cap field's release floor is now measured (added `2024-09-01-preview`
  per the lifecycle changelog; documented on the current chat view cited
  above — learn renders that page for the dated `2024-10-21` view value),
  but WHICH
  `reasoning_effort` values the deployed model actually accepts remains
  UNVERIFIED: the reasoning how-to's support table names effort values by
  model FAMILY (per-model notes like "xhigh works only with…"), not by the
  deployed model, and names no per-model cap floor. The live cell therefore
  sends NO `reasoning_effort` (omission is accepted by every model of this
  family that is known; an unsupported value would answer 400 before spend),
  and the field is pinned absent offline. The cap itself is witnessed by the
  live leg - too small answers 200 incomplete, usage present.
- Live acceptance of a real Entra token end to end, exact rate-limit bodies, and streaming usage
  reporting against a real deployment. The owner approved the paid run (option B,
  2026-11-24: the leg creates and destroys its own resource, lead-only); the first run
  (2026-11-25) created an account and stopped at the local-auth read-back above — no
  deployment and no chat request were made — so everything about the data-plane shape
  below this line remains UNVERIFIED until the re-run.
