using System.Runtime.Versioning;

// The live scaffold is a Linux tool: its secret-file contract is the Unix mode-600
// check, and it is never built or run by CI (tests/CredProx.LiveTests stays outside
// CredProx.slnx). Declaring the platform keeps the platform analyzers honest about
// the Unix file-mode calls instead of suppressing them.
[assembly: SupportedOSPlatform("linux")]
