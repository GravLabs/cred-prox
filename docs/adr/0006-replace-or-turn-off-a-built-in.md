# ADR-0006: Replacing or turning off a built-in

Status: Accepted (architect ruling 2026-11-18, M43 slice D; it answers M41 item 10)
Date: 2026-11-18

## Context

M41 item 10 asks whether a host can replace each built-in behavior, or turn it off, and not
only add its own beside it. A survey of every registration across the ten packages at
`b660948` found three groups:

- **Single services** that the pipeline consumes one of: the token cache, the secret source,
  the caller store, the caller-token mapper, the clock, the registries and the option
  instances. These are registered with `TryAdd*`, so a host that registers its own first
  wins. There is one deliberate exception: `CallerTokenOptions` is added with `AddSingleton`, so
  the last registration wins and the fail-closed `MaxTokenAge` bound always comes from
  configuration (ADR-0004). The forwarder client factory is public and not sealed, so a host can subclass it and
  register its own with `Replace` afterwards. The caller-token handler has a designed swap
  point, `registerScheme`. These paths work today, but nothing documents them as supported or
  tests them as such.
- **Pipeline stages** (request, response and outbound features) are registered with
  `TryAddEnumerable`. A host's own feature runs beside the built-in stages, never instead of
  one. The stages that are optional already have an options switch: scrubbing, error
  normalisation (global and per route), audit, health probes, and a per-route anonymous caller.
- **The fail-closed set:** header hygiene, credential attach, the operation allow-list, the
  kill switch, refresh-on-401, the startup validator and guards, and unknown-key refusal.
  These have no switch, and most cannot be replaced.

One existing switch is incomplete. `CredProx:Health:Enabled=false` stops the probes, but the
`credprox` health check stays registered and reports Healthy, saying that no probes have run.

## Decision

1. **Single services are replaced host-first.** Register your implementation before the
   `AddCredProx…` call, and it is the one used. This is a supported contract. It is
   documented in `docs/extending.md`, and each path has a test that resolves the host's
   implementation. No new API is added.
2. **Pipeline stages are extend-only.** A host adds stages; it does not replace a built-in
   one. CredProx adds no generic stage-suppression switch, and removing a built-in's service
   descriptor is unsupported. The stages are the security floor that ADR-0005 keeps in the
   core. If a hygiene, attach or scrub stage could be replaced, the library could no longer
   promise that a credential never reaches the upstream, or that a secret never reaches the
   caller.
3. **An optional stage is turned off only by its named switch.** The named switches are the
   ones listed above. New switches are added one at a time, for a stage that is optional and
   safe to turn off, never as a general mechanism.
4. **The fail-closed set has no off switch,** and the audit recorder, kill switch and
   outbound dispatch stay non-replaceable. The seam for audit is `IAuditSink`. The kill switch
   is core policy.
5. **A switch that says off is off.** With `CredProx:Health:Enabled=false`, neither the probe
   service nor the `credprox` health check is registered.

## Consequences

- The public API does not change, and APICompat stays on the 0.11.0 baseline.
- One behavior change: a host that turned health probes off no longer has a `credprox`
  health check. It previously reported Healthy without probing. CHANGELOG Changed.
- `docs/extending.md` gains a "Replace or turn off a built-in" table, with an honest
  answer for every built-in. Two interactions are documented: turning scrubbing off while
  error normalisation stays on lets un-scrubbed vendor bytes reach `vendor_detail`; and
  pre-registering `CallerKeyOptions` means the `CredProx:CallerAuth` config is no longer read.
- If a real host needs to replace a stage, that case reopens this ADR. It does not get an
  ad-hoc switch.
