# ADR-0004: Short-lived, scoped caller tokens for agents (Entra-first)

Status: Accepted (design; built in M39)
Date: 2026-11-15 (revised the same day: Entra-first, no built-in issuer)

## Context

CredProx already keeps vendor secrets away from callers. A caller authenticates to CredProx;
CredProx attaches the real vendor credential on the way out, and scrubs any echo of it on the
way back. What a caller holds today is a **caller API key**: long-lived, hashed in
configuration, and scoped by that caller's operation allow-list.

That fits services. It fits AI agents and other short-lived workers poorly:

- an agent run lasts minutes, but its key lasts until someone rotates it;
- the key is a secret the agent's host must store;
- a leaked key (a prompt-injection exfiltration, a log line, a crash dump) stays valid.

The wanted shape: an agent holds **no long-lived secret at all**, presents a **short-lived**
token, and can do only a **subset** of what its caller may do. It never sees a vendor secret.

## Decision

**Microsoft Entra ID issues the tokens; CredProx only validates and maps them.** CredProx
mints nothing and stores no token secret. Every Entra feature that already does a job is used
for it, and CredProx adds only a small claims-mapping layer. The validation path is standard
OpenID Connect, so any other OIDC issuer (Keycloak and others) works with the same
configuration. That is the interoperability guarantee, though Entra is the documented and
tested path.

| Need | Provided by |
|---|---|
| Agent identity, no stored secret | **Managed identity** (agents hosted in Azure), or **workload identity federation** (GitHub Actions, Kubernetes, other clouds). The agent's platform proves who it is; nothing to rotate. An app registration with a certificate is the fallback. |
| Token issuance and lifetime | Entra client-credentials access tokens: 60–90 minutes by default, shorter with an Entra token-lifetime policy on the CredProx API (minimum 10 minutes). |
| Scope | **App roles** defined on the CredProx API app registration and assigned to each agent identity. They arrive as the `roles` claim. |
| Signing keys and rollover | Entra's published OIDC metadata and JWKS, discovered and refreshed automatically. |
| Disable an agent | Remove its role assignment, or disable its service principal, in Entra. New tokens stop. |
| Agent-side code | **Azure.Identity** (`DefaultAzureCredential` / `ManagedIdentityCredential`): `GetTokenAsync(["api://<credprox-api>/.default"])`. There is no CredProx client package. |

What CredProx itself does:

1. **Validate with the stock ASP.NET Core JWT bearer handler**
   (`Microsoft.AspNetCore.Authentication.JwtBearer`). Configure the `Authority`
   (`https://login.microsoftonline.com/<tenant>/v2.0`) and the `Audience` (the CredProx API's
   app ID URI or client id). The framework checks the signature, issuer, audience, expiry and
   not-before.
2. **Map the token to a caller.** The client-app claim (`azp` for v2 tokens, `appid` for v1)
   must match an id listed on a defined caller in `CredProx:Callers`
   (`TokenClientIds: [<app or managed-identity client id>]`). An unlisted client is a `401`,
   even with a valid token: the CredProx configuration stays the allow-list of who may call.
3. **Scope only narrows.**
   - A caller's operation rules may carry a `Name`, which equals an Entra app-role value.
   - The effective rules for a request are the caller's rules **intersected with** the token's
     `roles` claim (and `scp`, for delegated user tokens). It is never the union.
   - A token with no matching role gets nothing; a role naming no rule grants nothing.
   - Everything downstream stays unchanged: the allow-list, per-caller credential mapping,
     budgets, the kill switch and audit. Audit records the caller id, the client id and the
     token id (`uti`/`jti`), never the token.
4. **An optional maximum token age** (`MaxTokenAge`, for example 15 minutes). It rejects a
   token older than the operator wants, measured from `iat`, even while Entra still considers
   it valid. Operators get a short window without depending on Entra's preview lifetime
   policies.
5. **Revocation.** Entra stops issuing new tokens (role removal, service principal disabled).
   An already-issued token stays valid until it expires or reaches `MaxTokenAge`. For
   immediate cut-off, the existing per-caller **kill switch** blocks a caller's tokens at once.
   Entra's continuous access evaluation is not relied on: for workload identities it applies
   to Microsoft Graph, not to custom APIs like CredProx.

**Granularity trade-off.** Entra client-credentials tokens carry every role assigned to that
identity. So scope narrows **per agent identity** (one managed identity or app registration
per agent type, with its own role assignments), not per individual agent run. That is
accepted. Per-run narrowing would need CredProx to mint its own tokens, and that was rejected
(below).

## Swappable layers

Each layer sits behind a standard ASP.NET Core extension point or one small CredProx
interface. Any layer can be replaced without touching the others, and the defaults are thin
wrappers over the framework.

| Layer | Default | Swap point |
|---|---|---|
| **Token validation** | ASP.NET Core JWT bearer handler, Entra `Authority` | An authentication scheme. Register another handler under the caller-token scheme: `Microsoft.Identity.Web` for multi-tenant Entra, another OIDC issuer, or an introspection handler. The policy accepts any scheme that yields a caller. |
| **Signing keys** | OIDC discovery (Entra JWKS) | Standard `TokenValidationParameters` / `IssuerSigningKeyResolver`. |
| **Claims to caller** | `azp`/`appid` matched against `TokenClientIds` | `ICallerTokenMapper`: turns the validated `ClaimsPrincipal` into a `CallerIdentity` plus an optional scope set. Replace it for a different claim layout or a caller directory. |
| **Caller directory** | The existing configured callers | The existing `ICallerStore` / caller registry. Tokens reuse it, with no second caller model. |
| **Scope enforcement** | Caller rules ∩ `roles`/`scp` | The existing operation allow-list stage reads an optional per-request scope set from the request features. Any authentication layer that sets that feature narrows the same way. |
| **Consumer side** | Azure.Identity | None needed: standard OAuth bearer tokens. Switching identity provider or client library changes nothing that calls CredProx. |

The rule for the build: no layer may reach past its neighbour. Validation knows nothing about
caller rules, the mapper knows nothing about signing, and enforcement only reads the
scope-set feature. Tests pin each layer in isolation and the default stack end to end.

## Consequences

- **Very little new code:** an options class, the claims-to-caller mapper, the scope-set
  intersection in the existing allow-list stage, the optional maximum-age check, and one
  registration extension. Signatures, key rollover, issuance and lifetimes are Entra's and the
  framework's.
- **New public surface:** the options class, the registration extension, the optional rule
  `Name`, `TokenClientIds` on callers, and `ICallerTokenMapper`. It is additive and marked
  `[Experimental]` like the other caller-auth types, so the release carrying it is a minor
  version.
- **Security-sensitive:** the milestone gets an adversarial review pass covering:
  - algorithm confusion and `none`;
  - wrong tenant, issuer or audience, and v1 vs v2 tokens;
  - expired, not-yet-valid and over-age tokens, and clock skew;
  - role widening, an unknown client id and a valid token for an unlisted client;
  - token leakage in logs and audit;
  - that caller API keys keep working unchanged.
- **The headline example (E19):** an agent obtains an Entra token with Azure.Identity and calls
  through CredProx, including the Entra setup (API app registration, app roles, assignment to
  a managed identity, `az` commands). Offline tests use a locally signed issuer that serves
  OIDC metadata, so no tenant is needed for CI. A live Entra run is optional and needs its own
  owner approval, as for the earlier live validations.

## Rejected options

- **A built-in CredProx token issuer, deferred as an optional future enhancement** (owner,
  2026-11-15). It would add a standard client-credentials token endpoint for teams without an
  identity provider, and would allow per-run scope narrowing. It is not in M39 because Entra
  already issues, signs, rotates and scopes. If it is built later, it plugs into the same
  validation path as one more token source (a locally signed issuer), so nothing in M39
  changes. Plan §8.2 tracks it.
- **`Microsoft.Identity.Web` as the default validator:** it is Entra-specific, while the stock
  JWT bearer handler validates Entra tokens and every other OIDC issuer. It stays available
  through the validation swap point (multi-tenant Entra is its natural use).
- **Opaque tokens with introspection:** a network hop per request, where JWTs validate
  locally.
- **Encoding scope as extra caller definitions only:** possible, but app roles are Entra's
  native scope mechanism and keep assignments in the identity provider.
