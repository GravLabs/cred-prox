namespace CredProx.LiveTests;

// The marker every live-gating Fact attribute carries (post-release item 7,
// 2026-11-25). The witness table in RunnerGateWitnessTests completes itself by
// reflection over this marker instead of the "LiveFactAttribute" NAME suffix,
// which was never the concept: renaming a live-gating attribute silently took
// its offline witness dark, and naming an ordinary attribute by the suffix
// drafted it into the live table. A new live-gating attribute implements this
// interface; MEASURED RESIDUAL, recorded not chased: a live gate added WITHOUT
// the marker is as invisible to the table guard as a renamed one was, and no
// offline check can read intent from a class that declares none — the marker
// declaration is the one-line act of will the guard demands.
public interface ILiveFactAttribute;
