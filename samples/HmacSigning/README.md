# HMAC request signing

The `Hmac` credential against a local signature-verifying stub. Nothing
external is needed: the stub vendor lives in the same process and verifies with an
independent implementation of the documented canonical-string layout — the way a real
vendor's verifier does.

## What it shows

- The canonical-string recipe as pure configuration (`appsettings.json`):
  `method`, `path`, `timestamp`, `bodyHash` joined by `\n`, HMAC-SHA256, lowercase hex.
- `SignatureHeader` / `TimestampHeader` placement; the signature replaces any
  caller-supplied value.
- Opt-in body buffering with a size cap: the `/small` route caps at 16 bytes, and a
  larger body answers `413 credprox.body_too_large_to_sign` without being forwarded.
- Signing runs at `Stage.Sign` — after header shaping and credential attachment — so
  the signature covers exactly what the vendor receives.

## Run the check (CI, no Docker)

One cell per behavior, driving the host over real sockets from
`tests/CredProx.SampleSmokes`:

```bash
dotnet test tests/CredProx.SampleSmokes --filter Sample=HmacSigning
# or the one-line wrapper:
cd samples/HmacSigning && ./smoke.sh
```

The cells post a signed body to the stub (the independent verifier answers
`signature valid`), then a body over the cap (413 with the documented code).

## Point it at a real vendor

Copy the `signer` credential block, set `Secret` to your vendor key reference, and adapt
`Components`, `Separator`, `Algorithm`, `Encoding` and the header names to the vendor's
documented scheme. The three component layouts proven by the test suite
(`tests/CredProx.Tests/HmacSignFeatureTests.cs`) cover the common shapes:
path+timestamp+body-hash, selected-headers, and query-included.
