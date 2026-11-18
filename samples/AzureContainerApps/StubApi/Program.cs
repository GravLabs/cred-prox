// The vendor stand-in the sample host proxies to: it answers every /acme path with a
// small payload and echoes the Authorization header it received verbatim — the exact
// value the gateway's response scrubber must redact before the caller sees it.
// /__last-auth hands the raw header to the offline cells; no real credential lives here.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var lastAuth = string.Empty;
app.Map("/acme/{**rest}", (HttpContext ctx) =>
{
    lastAuth = ctx.Request.Headers.Authorization.ToString();
    ctx.Response.ContentType = "application/json";
    return ctx.Response.WriteAsync(
        $"{{\"result\":{{\"item\":\"acme-widget\"}},\"saw_authorization\":\"{lastAuth}\"}}");
});
app.MapGet("/__last-auth", () => Results.Text(lastAuth));
app.Run();
