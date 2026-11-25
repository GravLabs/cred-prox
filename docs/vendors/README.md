# Vendor config snippets

One page per vendor: its auth model, the CredProx credential type it maps to, **one
complete copy-paste config block** using `secret:` references only, the required
secret names, scopes/audiences and the gotchas. These are **docs, not built-ins** —
the library ships no vendor presets (0.4 decision); a community preset
(`CredProx:Presets` or `IPresetSource`) can package a sample's fixed facts if you
want them as config sugar.

Every block here is machine-checked: `VendorSnippetValidationTests` extracts each
`json credprox-snippet` block from this folder and binds + validates it through the
real fail-closed startup path (unknown/misspelled keys refuse startup), so a snippet
can never rot into a config that fails at someone's deploy.

| Vendor | Auth model | CredProx type | Sample | Fact level |
|---|---|---|---|---|
| [Microsoft Graph](graph.md) | Entra client credentials or managed identity | `OAuthClientCredentials` / `TokenCredential` | [`samples/MicrosoftGraph`](../../samples/MicrosoftGraph/README.md) | sample + live M26 tenant-verified |
| [ADP](adp.md) | client credentials + mTLS on both hops | `OAuthClientCredentials` + `Connections` | [`samples/ADP`](../../samples/ADP/README.md) | sample-verified endpoints; portal facts UNVERIFIED |
| [Workday](workday.md) | JWT Bearer Grant (RFC 7523) to a tenant API client; PKCE is the user flow | `JwtAssertion` + `JwtBearerGrant` | — | grant type cited (doc.workday.com); endpoint/scopes **UNVERIFIED** |
| [Salesforce](salesforce.md) | Connected App OAuth 2.0 | `OAuthClientCredentials` (`FormPost`) | [`samples/AgentEgress`](../../samples/AgentEgress/README.md) | org metadata cited; flow enablement UNVERIFIED |
| [ServiceNow](servicenow.md) | per-instance OAuth 2.0 API client (client credentials) | `OAuthClientCredentials` | — | endpoint + grant cited; enablement property cited (KB1645212); scopes/lifetimes UNVERIFIED |
| [GitHub Apps](github-apps.md) | app JWT → installation token | `JwtAssertion` + `BearerExchange` | [`samples/GitHubApp`](../../samples/GitHubApp/README.md) | sample + vendor docs cited |
| [OpenAI](openai.md) | API key as bearer | `StaticKey` | [`samples/AiGateway`](../../samples/AiGateway/README.md) | vendor docs cited (2026-11-24); credential shape sample-verified |
| [Slack](slack.md) | bot token (`xoxb-…`) as bearer | `StaticKey` | — | vendor docs cited (2026-11-24); credential shape sample-verified |
| [Stripe](stripe.md) | secret/restricted API key (Basic or bearer) | `StaticKey` | — | vendor docs cited (2026-11-24); credential shape sample-verified |
| [Atlassian](atlassian.md) | Basic with email + API token | `StaticKey` (pre-encoded pair) | — | vendor docs cited (2026-11-24); Basic expressible with existing types |
| [Google APIs](google.md) | service-account JWT → OAuth token | `JwtAssertion` + `JwtBearerGrant` + `ScopeInAssertion` | [`samples/GitHubApp`](../../samples/GitHubApp/README.md) | vendor docs cited (2026-11-24); scope-in-claim placement pinned offline against a Google-shaped stand-in; live Google answers **UNVERIFIED** |

**Fact levels** (the honesty rule): a claim is *sample-verified* when a repo sample
or test proves it (cited as "verified in sample EX"), *cited* when a vendor's public
docs URL is given (fetched date noted), and marked **UNVERIFIED** otherwise — those
say "confirm against vendor docs" rather than guessing. Placeholders for
tenant-specific values are always `<like-this>`.
