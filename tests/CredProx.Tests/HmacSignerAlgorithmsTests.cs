using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Pins every non-default HMAC algorithm and signature-encoding arm. Each expected
/// value is computed inside the test straight from the BCL primitives — the
/// <c>HMACSHA*</c> classes, <see cref="Convert.ToHexString(byte[])"/> and
/// <see cref="Convert.ToBase64String(byte[])"/> — never through CredProx code, so the
/// signer's switch arms are checked against an independent reference rather than
/// against themselves.
/// </summary>
public sealed class HmacSignerAlgorithmsTests
{
    private const string Key = "reference-key-42";
    private const string Canonical = "POST\n/v1/orders\nx=1\n1763268000\npayload-hash-part";

    public static TheoryData<HmacAlgorithm, HmacSignatureEncoding> AllCombos => new()
    {
        { HmacAlgorithm.SHA256, HmacSignatureEncoding.HexLower },
        { HmacAlgorithm.SHA256, HmacSignatureEncoding.HexUpper },
        { HmacAlgorithm.SHA256, HmacSignatureEncoding.Base64 },
        { HmacAlgorithm.SHA384, HmacSignatureEncoding.HexLower },
        { HmacAlgorithm.SHA384, HmacSignatureEncoding.HexUpper },
        { HmacAlgorithm.SHA384, HmacSignatureEncoding.Base64 },
        { HmacAlgorithm.SHA512, HmacSignatureEncoding.HexLower },
        { HmacAlgorithm.SHA512, HmacSignatureEncoding.HexUpper },
        { HmacAlgorithm.SHA512, HmacSignatureEncoding.Base64 },
    };

    private static string EncodeBcl(byte[] bytes, HmacSignatureEncoding encoding) => encoding switch
    {
        HmacSignatureEncoding.HexLower => Convert.ToHexString(bytes).ToLowerInvariant(),
        HmacSignatureEncoding.HexUpper => Convert.ToHexString(bytes),
        HmacSignatureEncoding.Base64 => Convert.ToBase64String(bytes),
        _ => throw new ArgumentOutOfRangeException(nameof(encoding)),
    };

    [Theory]
    [MemberData(nameof(AllCombos))]
    public void Sign_MatchesBclReference(HmacAlgorithm algorithm, HmacSignatureEncoding encoding)
    {
        var options = new HmacOptions { Algorithm = algorithm, Encoding = encoding };
        var data = Encoding.UTF8.GetBytes(Canonical);
        var keyBytes = Encoding.UTF8.GetBytes(Key);

        var raw = algorithm switch
        {
            HmacAlgorithm.SHA256 => HMACSHA256.HashData(keyBytes, data),
            HmacAlgorithm.SHA384 => HMACSHA384.HashData(keyBytes, data),
            HmacAlgorithm.SHA512 => HMACSHA512.HashData(keyBytes, data),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };

        var actual = HmacSigner.Sign(Canonical, Key, options);

        Assert.Equal(EncodeBcl(raw, encoding), actual);
        if (encoding == HmacSignatureEncoding.Base64)
        {
            Assert.Equal(raw, Convert.FromBase64String(actual));
        }
        else
        {
            Assert.Equal(raw.Length * 2, actual.Length);
            Assert.All(actual, c => Assert.True(char.IsDigit(c) || c is >= 'a' and <= 'f' || c is >= 'A' and <= 'F'));
            // The case of the letters is decided by the equality above (the reference is
            // built with the same case); here only the alphabet is pinned.
        }
    }

    // The bodyHash component runs the same algorithm switch (ConvertHash); swapping an
    // arm there changes the canonical string, not the signature, so it needs its own pin.
    [Theory]
    [MemberData(nameof(AllCombos))]
    public void BodyHashComponent_MatchesBclReference(HmacAlgorithm algorithm, HmacSignatureEncoding encoding)
    {
        var body = Encoding.UTF8.GetBytes("order-payload-42");
        var options = new HmacOptions { Algorithm = algorithm, Encoding = encoding, Separator = "|" };
        var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.example/v1/orders");

        var canonical = HmacSigner.BuildCanonicalString(
            [(HmacComponentKind.BodyHash, string.Empty)], request, body, options, DateTimeOffset.UnixEpoch);

        var rawHash = algorithm switch
        {
            HmacAlgorithm.SHA256 => SHA256.HashData(body),
            HmacAlgorithm.SHA384 => SHA384.HashData(body),
            HmacAlgorithm.SHA512 => SHA512.HashData(body),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };

        Assert.Equal(EncodeBcl(rawHash, encoding), canonical);
    }
}
