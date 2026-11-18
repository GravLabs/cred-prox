using CredProx;

// The plugin host: one custom credential type ("VendorSession") registered explicitly —
// no discovery, no magic. VendorSessionProvider.cs is the whole plugin; StubApi/ is the
// offline vendor the cells drive; the conformance suite ships beside the provider.
var builder = WebApplication.CreateBuilder(args);

// A plugin-only host supplies what its provider takes from DI — here the standard
// HttpClient machinery. Registration is the plugin's entire footprint in the host.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddHttpClient();
builder.Services.AddCredProxCredentialType<VendorSessionProvider, VendorSessionOptions>("VendorSession");
builder.Services.AddCredProxCredentials(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
