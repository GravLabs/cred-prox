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

One boundary rule to know when you pick `Separator`: a request is signed only while the
canonical string binds its boundaries. If a signed header, path or query value contains
the configured separator — or one value of a multi-value header contains the `,` that
joins its values — two distinct requests would sign identically, so CredProx refuses
that request with a 422 `credprox.canonical_ambiguous` problem response rather than
emit a signature the vendor cannot pin to one request. Prefer a separator that cannot
occur in your values; the newline default satisfies that for validated header values.
Nothing changes for requests whose values carry no separator. An empty `Separator`
is accepted for vendor schemes that sign a bare concatenation of the components. The
separator check cannot apply then — every value contains the empty string — so such
requests keep being signed and each credential configured that way logs one startup
warning naming it; the other ambiguity refusals still apply (a multi-value header
whose values contain a comma, or a signed name carried on both header collections).
