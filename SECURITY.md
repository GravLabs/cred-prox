# Security policy

CredProx is a credential-handling reverse proxy: it holds vendor secrets, issues and caches
tokens, and decides which caller may reach which upstream. Security problems here are taken
seriously even though the project is pre-1.0.

## Reporting a vulnerability

Report security issues as issues on the GitHub repository:
<https://github.com/GravLabs/cred-prox/issues>.

- Put `SECURITY:` at the start of the issue title so it is triaged first.
- Describe the weakness and its impact; do not publish working exploit code in the issue.
- **Never include real secrets** — vendor tokens, client secrets, caller keys, Key Vault
  URLs with SAS tokens — in any issue, public or not. Use placeholders
  (`<client-secret>`) in config excerpts and logs. This applies to non-security issues too.

This is a small project without a formal embargo process. If you would like time before
public discussion, say so in the issue and the maintainer will coordinate the fix and the
disclosure timeline with you.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x (current) | ✅ fixes land on `main` and ship in the next release |
| < 0.3 | ❌ pre-release; upgrade |

There are no backport branches yet. Fixes ship forward.

## What counts as a vulnerability

The security boundaries CredProx promises (plan §3, §5.2):

- **Secret scoping** — a credential can only resolve the `secret:` references its
  configuration declares; one credential must not read another's secrets.
- **Secret non-leakage** — secret values never appear in logs, error messages, audit
  records, or exception text.
- **Caller authentication** — caller API keys are compared in constant time; an
  unauthenticated or unknown caller gets no upstream request; operation allow-lists are
  enforced fail-closed.
- **Destination allow-lists** — a templated destination cannot be steered outside its
  declared allow-list (including via encoded or normalized path/host tricks).
- **Header hygiene** — inbound `Authorization` and caller keys are not forwarded to
  upstreams; injected credential headers replace, never duplicate.
- **Token cache isolation** — cache entries are keyed per credential and partition; one
  partition never receives another's token.

Anything that breaks one of these is a vulnerability even if it "only" works from a
maliciously crafted configuration.

## Out of scope

- Attacks on the host machine or the configuration store you put CredProx in front of.
- Vulnerabilities in dependencies (YARP, .NET) — report those upstream; CredProx updates
  its dependencies through normal servicing.
- Hardening advice for your deployment (that lives in the sample READMEs).
