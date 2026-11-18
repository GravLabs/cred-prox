# CredProx.Hmac

HMAC signing add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Signature-style `Hmac` credential type** — a shared key plus the canonical-string
  recipe the signing stage applies at `Stage.Sign`. The key is never attached to the
  request; only the computed signature header is.
- **A recipe, not a fixed scheme** — `Components` picks the canonical-string entries
  (`method`, `path`, `query`, `timestamp`, `bodyHash`, `header:<Name>`) and their
  `Separator`; `Algorithm` (default SHA-256) and `Encoding` (default lower hex) shape the
  signature; `SignatureHeader` names the header it replaces, with optional
  `TimestampHeader` and `SchemePrefix` so a verifier can check without parsing.
- **The key is a `secret:` reference or a literal**, resolved through the credential's
  scoped accessor by the core's shared rule — never attached, logged or placed in an
  error message.
- **`bodyHash` is opt-in** — computing it buffers the outbound body, which conflicts
  with streaming, so the credential must say so explicitly.

## Setup

```csharp
builder.Services.AddCredProx(builder.Configuration); // core defaults, one call
builder.Services.AddCredProxHmac();
```

Configuration keeps `Type: Hmac` unchanged (see the
[`HmacSigning` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/HmacSigning)).
A credential naming `Type: Hmac` without this package fails startup naming the package
to add — the core keeps no type knowledge here beyond that hint.

## License

MIT
