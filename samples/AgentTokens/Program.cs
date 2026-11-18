var builder = WebApplication.CreateBuilder(args);

// The deployable host: AddCredProx registers the core defaults, the CallerTokens call
// validates agent OIDC tokens against the Authority in appsettings.json, and YARP serves
// the proxy from config. Who gets admitted to what is explained in the README.
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxCallerTokenAuthentication(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();

app.MapReverseProxy();
app.Run();
