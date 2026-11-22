using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Contributes derived data about the caller registry that a feature package owns and the
/// core must not learn — the write-side twin of <see cref="CredProx.Abstractions.ICallerRegistryValidator"/>.
/// The core runs every registered contributor inside the bind that accepted the registry:
/// once when the provider performs its initial bind (so a contributor that fails refuses
/// host startup), and once again on every live configuration rebind that the validators
/// accepted. Whatever a contributor returns is committed together with the registry as one
/// <see cref="CallerRegistryGeneration"/> and swapped atomically — a request never sees a
/// registry from one configuration with another configuration's contributed data, and a
/// rebind that any contributor refuses leaves the previous generation (registry and all
/// contributed data) serving unchanged.
/// </summary>
/// <remarks>
/// <para>
/// A contributor sees only the accepted <see cref="CallerRegistry"/> — configuration the
/// validators refused never reaches it. Register through
/// <c>WithCallerRegistryContributor&lt;TContributor&gt;()</c> (or the plain singleton
/// registration), the same way validators are contributed.
/// </para>
/// <para>
/// A contributor that throws refuses the whole bind, with the same consequences on either
/// path as a throwing validator: startup fails, or the previous generation keeps serving
/// and one error line names the reason. Like validators, contributors must treat
/// configuration values as secrets — never store, log or carry them into exception text.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public interface ICallerRegistryContributor
{
    /// <summary>
    /// Builds this contributor's data for the accepted registry, inside the bind that
    /// accepted it. The build is plainly synchronous: the core runs it inside the bind,
    /// which itself runs inside a configuration-change callback — there is nothing to
    /// cancel there, so the contract carries no cancellation token.
    /// </summary>
    /// <param name="registry">The registry the bind just accepted; the generation is committed against this exact instance.</param>
    /// <returns>The data to commit with the registry; retrievable from the generation by contributor type.</returns>
    object Contribute(CallerRegistry registry);
}
