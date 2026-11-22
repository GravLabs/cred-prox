using CredProx;

// The CredProx host of the PerCallerCredentials example: caller keys, the caller-partitioned
// OAuth credential, the allow-lists and the audit sink are all appsettings.json — the host
// is one entry plus the add-on chain it needs. The vendor API behind it is StubApi/.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity()
    .AddOperations();
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
