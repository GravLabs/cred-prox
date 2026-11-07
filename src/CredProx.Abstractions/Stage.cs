using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// The fixed request-processing stages of CredProx. Plugins declare the stage they run
/// in; the core enforces the order regardless of registration order
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 3).
/// </summary>
/// <remarks>
/// Values are spaced by ten so that stages can be inserted between existing ones
/// without renumbering.
/// </remarks>
[Experimental("CREDPROX001")]
public enum Stage
{
    /// <summary>Authenticate the caller (for example an inbound API key). Runs first.</summary>
    AuthenticateCaller = 0,

    /// <summary>
    /// Enforce the operational kill switch (M18, plan §8.4): a cluster or a caller taken
    /// out of service by configuration answers <c>503</c> here. Runs after caller
    /// authentication — a disabled caller must still present a valid key, the switch is
    /// not an anonymous bypass — and before everything that could touch a partition
    /// source, a token endpoint or the upstream.
    /// </summary>
    ApplyKillSwitch = 5,

    /// <summary>Authorize the authenticated caller for this operation (route, method, path).</summary>
    AuthorizeOperation = 10,

    /// <summary>Resolve the outbound destination, including partition allow-listing.</summary>
    ResolveDestination = 20,

    /// <summary>
    /// Apply the authenticated caller's request budget (M15, plan §3.7). Runs after the
    /// destination is resolved (per-cluster overrides key on the resolved cluster) and
    /// before header shaping and credential attachment, so a budget-rejected request never
    /// touches a token endpoint or the upstream.
    /// </summary>
    ApplyCallerBudget = 25,

    /// <summary>Add, remove or rewrite request headers before the credential is attached.</summary>
    ShapeHeaders = 30,

    /// <summary>Attach the outbound credential (token, key or signature input).</summary>
    AttachCredential = 40,

    /// <summary>
    /// Sign the request. Runs after every other change to the request, because a
    /// signature computed over an earlier form of the request would be invalid.
    /// </summary>
    Sign = 50,

    /// <summary>The outbound pipeline: throttling, resilience, audit.</summary>
    Pipeline = 60,

    /// <summary>Send the request upstream. Runs last on the way out.</summary>
    Send = 70,

    /// <summary>
    /// Inspect or modify the response received from upstream before the caller sees any
    /// of it (M20, plan §8.2). The first built-in at this stage is response secret
    /// scrubbing; plugins reach it by implementing <see cref="IResponseFeature"/>.
    /// </summary>
    ShapeResponse = 80,
}
