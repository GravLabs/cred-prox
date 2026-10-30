using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Guards the shape of the plugin contract: every public type in
/// <c>CredProx.Abstractions</c> is marked <c>[Experimental("CREDPROX001")]</c>
/// (plan §3.5 rule 7), and the contract is interfaces, enums, pure data holders
/// (classes or records) and sealed signal exceptions — no behavior implementations.
/// </summary>
public class AbstractionsContractTests
{
    private static readonly Type[] ExpectedContractTypes =
    [
        typeof(ICredentialProvider<>),
        typeof(ISecretSource),
        typeof(ISecretAccessor),
        typeof(IPartitionSource),
        typeof(IPartitionSourceFactory),
        typeof(ITokenCache),
        typeof(IRequestFeature),
        typeof(IResponseFeature),
        typeof(IConnectionFeature),
        typeof(IPipelineFeature),
        typeof(IAuditSink),
        typeof(ICredentialHealthProbe),
        typeof(IPresetSource),
        typeof(CredentialRequestContext),
        typeof(Stage),
        typeof(ICallerStore),
        typeof(CallerKeyMatch),
        typeof(CallerIdentity),
        typeof(PartitionRejection),
        typeof(CredProxHealthSeverity),
        typeof(CredProxHealthResult),
        typeof(PipelineFeatureContext),
        typeof(InboundTokenRejectedException),
        typeof(ConsentRequiredException),
    ];

    // Pure data holders allowed alongside the interfaces: no behavior, init-only state.
    private static readonly Type[] DataTypes =
    [
        typeof(CredentialRequestContext),
        typeof(CallerKeyMatch),
        typeof(CallerIdentity),
        typeof(CredProxHealthResult),
        typeof(PipelineFeatureContext),
    ];

    // Contract signal types: sealed exceptions a provider throws to signal a documented
    // outcome the core maps (§3.6: InboundTokenRejectedException → 401; §8.3:
    // ConsentRequiredException → 401 consent_required). State-only — no behavior beyond
    // Exception plumbing.
    private static readonly Type[] SignalTypes =
    [
        typeof(InboundTokenRejectedException),
        typeof(ConsentRequiredException),
    ];

    private static Assembly AbstractionsAssembly => typeof(IRequestFeature).Assembly;

    [Fact]
    public void EveryPublicType_IsMarkedExperimental()
    {
        var publicTypes = AbstractionsAssembly.GetExportedTypes();
        Assert.NotEmpty(publicTypes);

        foreach (var type in publicTypes)
        {
            var attribute = type.GetCustomAttribute<ExperimentalAttribute>();
            Assert.True(
                attribute is not null,
                $"{type.FullName} is missing [Experimental(\"CREDPROX001\")].");
            Assert.Equal("CREDPROX001", attribute!.DiagnosticId);
        }
    }

    [Fact]
    public void Contract_ContainsExactlyTheExpectedTypes()
    {
        var exported = AbstractionsAssembly.GetExportedTypes();

        foreach (var expected in ExpectedContractTypes)
        {
            Assert.Contains(expected, exported);
        }

        Assert.Equal(ExpectedContractTypes.Length, exported.Length);
    }

    [Fact]
    public void Contract_ContainsNoImplementations()
    {
        foreach (var type in AbstractionsAssembly.GetExportedTypes())
        {
            Assert.True(
                type.IsInterface || type.IsEnum || DataTypes.Contains(type) || SignalTypes.Contains(type),
                $"{type.FullName} is not an interface, an enum, a declared data type, or a signal exception; Abstractions must stay implementation-free.");
        }
    }

    [Fact]
    public void DataTypes_HaveNoBehavior()
    {
        foreach (var type in DataTypes.Concat(SignalTypes))
        {
            Assert.True(type.IsSealed, $"{type.FullName} must be sealed.");
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                // Record-synthesized value semantics (Equals/GetHashCode/ToString/clone)
                // are generated data plumbing, not behavior.
                if (method.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false))
                {
                    continue;
                }

                Assert.True(
                    method.IsSpecialName,
                    $"{type.FullName}.{method.Name} is behavior; data types may expose properties only.");
            }
        }
    }
}
