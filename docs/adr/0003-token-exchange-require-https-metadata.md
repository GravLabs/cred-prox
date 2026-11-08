# ADR-0003: TokenExchange requires https for inbound-validation key material by default

Date: 2026-11-08
Status: accepted (M31 review, ruling on finding P-7)

## Context

`TokenExchange` (design §3.6) validates the **inbound** user token itself —
signature, issuer, audience, lifetime — before trusting its subject, so the key
material it fetches (the authority's OIDC discovery document, or a directly
configured `JwksUri`) is the root of the per-user cache key's non-forgeability.

M31's mutation triage found the whole discovery cluster untested (finding P-7):
the metadata fetch ran on Wilson's own retriever outside the stubbed
`IHttpClientFactory`, rejecting non-https metadata (`IDX20108`) while the
startup validators accept http endpoints across the product. A valid
`Authority: http://keycloak.internal/realms/x` booted clean and then failed
every request. The first fix made the retriever contradict-http-free: it rode
the credential's per-connection egress client with `RequireHttps = false`,
aligning with the product-wide "endpoints may be http on private networks"
stance.

That stance is right for **outbound** token endpoints — fetching a vendor token
over http leaks nothing the network attacker does not already get from the
request itself, and private networks are a supported topology. It is wrong for
the keys that **validate inbound user tokens**: over plain http anyone on the
network path can serve a JWKS under their own control, forge a user token, and
have CredProx exchange it. ASP.NET Core's JwtBearer defaults
`RequireHttpsMetadata = true` for exactly this reason.

## Decision

(2026-11-08, ruling on M31 P-7.) Keep the accepted half of the P-7 fix — the
metadata fetch rides the credential's per-connection egress client, cached per
authority and connection — and make https the default for the inbound-validation
paths via a new additive option:

- `TokenExchangeOptions.RequireHttpsMetadata` (bool, **default `true`**)
  governs the authority discovery document **and** any directly configured
  `JwksUri` used for inbound validation.
- The startup validator refuses an http `Authority` or `JwksUri` unless the
  option is `false`; the refusal names the option. A §3.2 template that hides
  the scheme passes startup; the runtime fetch fails closed on the expanded
  value (Wilson's `RequireHttps` for discovery, the provider's own guard for
  direct JWKS).
- With `RequireHttpsMetadata = false`, http works through
  `HttpDocumentRetriever { RequireHttps = false }` on the connection client —
  the supported private-IdP configuration the first fix targeted.
- The manager cache key includes the flag: an opted-out credential cannot hand
  its http-tolerant manager to a credential that stayed on the default.

## Consequences

- The original P-7 bug shape (boots clean, fails every request) is fixed in the
  stronger direction: http metadata configs fail at startup with an actionable
  message instead of at runtime.
- A library behaviour change against 0.8.x: http IdP deployments that worked
  with the first fix's default now need the explicit opt-out. It is in the
  `Unreleased` CHANGELOG entry; `samples/TokenExchange` (E14) opts out with a
  comment because its Keycloak metadata is http on the private docker network.
- Unknown-key binding and coverage gates are unchanged; the option is additive
  (APICompat-clean against the published baseline).
