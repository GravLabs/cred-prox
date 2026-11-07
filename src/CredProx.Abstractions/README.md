# CredProx.Abstractions

The plugin contract for [CredProx](https://github.com/GravLabs/cred-prox): the interfaces a
credential-type plugin, secret source, preset source, partition source, audit sink or
pipeline feature implements. This package has no dependencies beyond .NET and no
implementation — implement it against a released `CredProx` and your plugin needs no
fork of the library.

The contract is versioned with the library and frozen in shape while `CredProx` is on a
`0.3.x` minor; APIs marked `[Experimental]` may change before 1.0.

## What you can build

| Interface | You provide |
|---|---|
| `ICredentialProvider` | a new credential type (vendor auth flow) |
| `ISecretSource` | a new secret store (vault, KMS, database) |
| `IPresetSource` | vendor presets as data, without touching the library |
| `IPartitionSource` | per-tenant/per-environment partitioning |
| `IAuditSink` | where credential-use audit records go |
| `IPipelineFeature` / `IRequestFeature` / `IResponseFeature` / `IConnectionFeature` | pipeline behaviour at a declared `Stage` |
| `ITokenCache` | a distributed token cache backing |
| `ICallerStore` | caller identity from somewhere other than configuration |
| `ICredentialHealthProbe` | vendor-specific health checking |

Providers can also name an outcome precisely with the sealed signal exceptions:
`InboundTokenRejectedException` becomes `401 credprox.inbound_token_invalid`, and
`ConsentRequiredException(authorizeUrl)` becomes `401 credprox.consent_required` with the
URL as the problem's `authorize_url` member — anything else is the generic
`502 credprox.credential_unavailable`.

## Start here

[`samples/CustomPlugin`](https://github.com/GravLabs/cred-prox/tree/main/samples/CustomPlugin)
is a complete custom credential type in ~50 lines, registered explicitly and tested with
the `CredProx.Testing` conformance suites — the template for community plugins.

## License

MIT
