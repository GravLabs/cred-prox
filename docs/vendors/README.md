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
| [ADP](adp.md) | client credentials + mTLS on both hops | `OAuthClientCredentials` + `Connections` | [E6](../../samples/ADP/README.md) | sample-verified endpoints; portal facts UNVERIFIED |
| [Workday](workday.md) | JWT Bearer Grant (RFC 7523) to a tenant API client; PKCE is the user flow | `JwtAssertion` + `JwtBearerGrant` | — | grant type cited (doc.workday.com); endpoint/scopes **UNVERIFIED** |
| [Salesforce](salesforce.md) | Connected App OAuth 2.0 | `OAuthClientCredentials` (`FormPost`) | [E15](../../samples/AgentEgress/README.md) | org metadata cited; flow enablement UNVERIFIED |
| [ServiceNow](servicenow.md) | per-instance OAuth 2.0 API client (client credentials) | `OAuthClientCredentials` | — | endpoint + grant cited; enablement property cited (KB1645212); scopes/lifetimes UNVERIFIED |
| [GitHub Apps](github-apps.md) | app JWT → installation token | `JwtAssertion` + `BearerExchange` | [E8](../../samples/GitHubApp/README.md) | sample + vendor docs cited |
| [Microsoft Graph](graph.md) | Entra client credentials or managed identity | `OAuthClientCredentials` / `TokenCredential` | [E5](../../samples/MicrosoftGraph/README.md) | sample + live M26 tenant-verified |
| [Spotify](spotify.md) | client credentials, Basic auth | `OAuthClientCredentials` | [E4](../../samples/Spotify/README.md) | sample-verified |

**Fact levels** (the honesty rule): a claim is *sample-verified* when a repo sample
or test proves it (cited as "verified in sample EX"), *cited* when a vendor's public
docs URL is given (fetched date noted), and marked **UNVERIFIED** otherwise — those
say "confirm against vendor docs" rather than guessing. Placeholders for
tenant-specific values are always `<like-this>`.
