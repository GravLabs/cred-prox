var builder = WebApplication.CreateBuilder(args);

// The deployable CredProx host: AddCredProx registers the core defaults (token cache, the
// configuration-backed secret source, the built-in credential types, and the credentials and
// destinations below), and YARP serves the proxy from config. The README walks the request.
builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();

app.MapReverseProxy();
app.Run();
