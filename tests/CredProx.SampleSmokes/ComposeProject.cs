using System.Security.Cryptography;
using System.Text;

namespace CredProx.SampleSmokes;

// The docker compose project name for this checkout. Compose derives the default
// project name from the compose file's directory, which is identical in every
// checkout — two checkouts on one machine would share (and fight over) one stack.
// A short hash of the checkout's repo root scopes every stack to its own checkout.
public static class ComposeProject
{
    public static string NameFor(string repoRoot)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(repoRoot));
        return "credprox-" + Convert.ToHexString(hash)[..8].ToLowerInvariant();
    }
}
