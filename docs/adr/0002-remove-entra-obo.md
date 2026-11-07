# ADR-0002: Remove the Entra on-behalf-of exchange mode

Date: 2026-11-03
Status: accepted (M27, maintainer decision)

## Context

M14 shipped the `TokenExchange` credential type with two wire shapes selected by
`TokenExchangeMode`: `Rfc8693` (generic RFC 8693 token exchange) and `EntraObo`
(Microsoft's on-behalf-of profile — `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
the inbound token sent as `assertion`, plus `requested_token_use=on_behalf_of`).

On 2026-11-03 the maintainer decided to remove OBO from the library: *"this is not really
needed, remove it and the examples. Keep all the other azure features."* The decision
followed M26 (live Azure/Entra validation): the OBO path was the one shipped shape whose
live proof required a tenant sign-in sitting, and under the tenant's real constraints
(Graph strips `publicClient.enabled`; new delegated scopes default `type=Admin`) the
consent-free device-code validation could not complete inside two windows. The M26
Phase 3 was dropped by the same decision.

Design weight on the way out: OBO was a draft-era profile of RFC 8693 — a different
grant URN, a different assertion parameter name, one extra form field. Everything else
(inbound validation, per-user cache, client auth, field-name overrides) is shared. The
one profile that was vendor-specific was also the only one whose deviation the config
knobs could not already express — and that residual gap is exactly what the provider
plugin point exists for.

## Decision

- Remove `TokenExchangeMode.EntraObo` and the jwt-bearer form branch from
  `TokenExchangeProvider`.
- **Keep** `TokenExchangeMode` as a single-member enum (`Rfc8693`). Existing config
  naming `Mode: Rfc8693` keeps binding; removing the property would break every
  `TokenExchange` credential for no requested reason.
- A config still naming the removed mode fails loudly at startup binding
  (`ConfigurationBinder` refuses the unknown enum value;
  `CredentialRegistryProviderTests.RemovedEntraOboMode_FailsStartupBinding` pins that
  it never degrades to a silent RFC 8693 exchange). The numeric spelling is the binder's
  blind spot — any number binds — so `TokenExchangeOptionsValidator` separately refuses
  undefined `Mode` values (`Enum.IsDefined`), pinned by
  `CredentialRegistryProviderTests.NumericUndefinedMode_FailsStartupValidation`.
- APICompat: the member is `[Experimental("CREDPROX001")]`, but SDK 10's APICompat has
  no experimental awareness (ADR-0001 context) — the removal surfaces CP0002 like any
  other member removal.
  A scoped suppression for exactly this member rode
  `src/CredProx/CompatibilitySuppressions.xml` while the baseline predated the removal;
  from the `0.8.0` baseline (0.8.1) it can no longer fire and the file is deleted.
  Every other removal still bites.

Unchanged, deliberately: the `TokenExchange` type itself, M14 inbound-token validation,
the per-user cache, example E14 (Rfc8693 against Keycloak), `JwtAssertion`'s jwt-bearer
client authentication (RFC 7523 client auth — not OBO, unrelated grant), and every other
Azure feature (DefaultAzureCredential, Entra client-credentials, Key Vault secret
source).

## Migration

`Mode: EntraObo` has no replacement mode. Anyone exchanging at Entra's on-behalf-of
endpoint implements a custom `ICredentialProvider` posting the three-field form (the
provider plugin point, plan §3.5/§3.6); the inbound-validation pattern in
`TokenExchangeProvider` applies unchanged. For most callers this is not reachable: the
same user-delegated token Entra mints for OBO is obtainable client-credentials-style
where the proxy can re-assert, and non-Microsoft IdPs speak RFC 8693.

## Consequences

- The public surface loses one enum member — acceptable pre-1.0 for `[Experimental]`
  API (CHANGELOG `Unreleased → Removed` flags the breaking change).
- The plan §3.6 becomes one-shape prose; M14 history rows stay annotated
  "OBO removed in M27".
- M26 Phase 3 / the e14 tenant scaffolding went away with the same decision;
  the battery is phases 1/2/4.
