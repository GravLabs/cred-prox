using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// The agent client of the AgentTokens sample: a real tool-calling loop over the Anthropic
// Messages API, and it holds NOTHING but its own Entra bearer token. It has no Anthropic
// key and cannot see one — CredProx validates the token, enforces the caller's operation
// allow-list, attaches the vendor key (x-api-key) on the model route, and strips this
// agent's bearer before the request reaches the provider (journal-proven in the smokes).
// One tool is on the allow-list (docs); one deliberately is not (GitHub meta) — when the
// proxy answers 403 the agent sees it as a tool error and carries on. That refusal IS the
// example. Raw HttpClient on purpose: no SDK here hides a secret the agent must not hold.
//
// Offline demo (see README): set AGENT_TOKEN to a token the stub issuer signs and point
// CREDPROX_URL at the sample host. For real use set AGENT_TENANT_ID / AGENT_CLIENT_ID /
// AGENT_CLIENT_SECRET / AGENT_API_SCOPE instead — the same Entra client-credentials grant
// any daemon in your fleet would use. No vendor credential exists in this process either way.

var proxyUrl = Environment.GetEnvironmentVariable("CREDPROX_URL") ?? "http://localhost:5096";
var model = Environment.GetEnvironmentVariable("AGENT_MODEL") ?? "claude-haiku-5-5";
var bearer = Environment.GetEnvironmentVariable("AGENT_TOKEN") ?? await AcquireEntraTokenAsync();
if (bearer is null)
{
    Console.WriteLine("agent: no Entra token — set AGENT_TOKEN, or AGENT_TENANT_ID, AGENT_CLIENT_ID, AGENT_CLIENT_SECRET and AGENT_API_SCOPE.");
    return 2;
}

using var http = new HttpClient { BaseAddress = new Uri(proxyUrl) };

var tools = new JsonArray
{
    new JsonObject
    {
        ["name"] = "fetch_docs",
        ["description"] = "Fetch a document from the internal docs service through the proxy.",
        ["input_schema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject { ["path"] = new JsonObject { ["type"] = "string" } },
            ["required"] = new JsonArray("path"),
        },
    },
    new JsonObject
    {
        ["name"] = "github_meta",
        ["description"] = "Report GitHub's public meta endpoints through the proxy.",
        ["input_schema"] = new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() },
    },
};

// A fixed, short prompt keeps a live run to a few cents and the transcript readable.
var messages = new JsonArray
{
    new JsonObject
    {
        ["role"] = "user",
        ["content"] = "Summarise the docs readme in one short sentence using fetch_docs, then try github_meta and tell me in one sentence whether it worked.",
    },
};

const int maxTurns = 4;
for (var turn = 1; turn <= maxTurns; turn++)
{
    var response = await AskModelAsync(messages);
    if (response is null)
    {
        return 1; // AskModelAsync already said why.
    }

    var content = response["content"]!.AsArray();
    messages.Add(new JsonObject { ["role"] = "assistant", ["content"] = content.DeepClone() });

    if (response["stop_reason"]?.GetValue<string>() != "tool_use")
    {
        foreach (var block in content)
        {
            if (block!["type"]?.GetValue<string>() == "text")
            {
                Console.WriteLine($"agent: {block["text"]!.GetValue<string>()}");
            }
        }

        return 0;
    }

    var toolResults = new JsonArray();
    foreach (var block in content)
    {
        if (block!["type"]?.GetValue<string>() != "tool_use")
        {
            continue;
        }

        var name = block["name"]!.GetValue<string>();
        var (status, body) = await RunToolAsync(name, block["input"]!);
        var isError = status is < 200 or >= 300;
        Console.WriteLine(isError
            ? $"tool {name} -> refused: the proxy answered HTTP {status}"
            : $"tool {name} -> OK (HTTP {status})");
        toolResults.Add(new JsonObject
        {
            ["type"] = "tool_result",
            ["tool_use_id"] = block["id"]!.GetValue<string>(),
            ["content"] = Truncate(body),
            ["is_error"] = isError,
        });
    }

    messages.Add(new JsonObject { ["role"] = "user", ["content"] = toolResults });
}

Console.WriteLine("agent: the tool loop never reached a final answer.");
return 1;

// One Anthropic Messages call, sent with NOTHING but this agent's Entra bearer. The
// provider key is CredProx's business, not ours — and so is the vendor's version
// header: the model route Sets it to the pinned value, which is what keeps a foreign
// caller of this front off Anthropic's 400 too.
async Task<JsonObject?> AskModelAsync(JsonArray conversation)
{
    // JsonNodes keep the parent they were first attached to, so each request gets its
    // own copies of the conversation and tool defs rather than the shared instances.
    var payload = new JsonObject
    {
        ["model"] = model,
        ["max_tokens"] = 256,
        ["messages"] = conversation.DeepClone(),
        ["tools"] = tools.DeepClone(),
    };
    using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages")
    {
        Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json"),
    };
    request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);

    using var response = await http.SendAsync(request);
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($"agent: the model call was refused with HTTP {(int)response.StatusCode}.");
        return null;
    }

    return JsonNode.Parse(text)!.AsObject();
}

// Both tools are plain GETs through the SAME proxy with the SAME token. Whether one is
// allowed is pure configuration: the meta route is not in the caller's operations, so
// the proxy refuses it with 403 before connecting anywhere — a tool error, not a crash.
async Task<(int Status, string Body)> RunToolAsync(string name, JsonNode input)
{
    var path = name switch
    {
        "fetch_docs" => "/docs/" + (input["path"]?.GetValue<string>() ?? "readme"),
        "github_meta" => "/meta",
        _ => "/docs/readme",
    };
    using var request = new HttpRequestMessage(HttpMethod.Get, path);
    request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
    try
    {
        using var response = await http.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }
    catch (HttpRequestException e)
    {
        return (0, $"unreachable: {e.Message}");
    }
}

// The real-world token path: Entra's v2 client-credentials grant, raw HttpClient — the
// token the agent authenticates with, fetched without any long-lived secret in the proxy's
// config. (On Azure you would use DefaultAzureCredential; same token, fewer lines.)
async Task<string?> AcquireEntraTokenAsync()
{
    var tenant = Environment.GetEnvironmentVariable("AGENT_TENANT_ID");
    var clientId = Environment.GetEnvironmentVariable("AGENT_CLIENT_ID");
    var secret = Environment.GetEnvironmentVariable("AGENT_CLIENT_SECRET");
    var scope = Environment.GetEnvironmentVariable("AGENT_API_SCOPE");
    if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(clientId)
        || string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(scope))
    {
        return null;
    }

    using var tokenHttp = new HttpClient();
    var form = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = clientId,
        ["client_secret"] = secret,
        ["scope"] = scope,
    });
    using var response = await tokenHttp.PostAsync(
        $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", form);
    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($"agent: Entra refused the token request with HTTP {(int)response.StatusCode}.");
        return null;
    }

    using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    return document.RootElement.GetProperty("access_token").GetString();
}

static string Truncate(string text) =>
    text.Length <= 500 ? text : text[..500] + "…";
