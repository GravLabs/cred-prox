using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// The local-model agent: it knows a gateway URL, its own bearer token, and a model
// name — nothing else. The bearer is the agent's Entra access token (the caller-token
// path, ADR-0004): CredProx validates it, maps its client id to the agent's caller
// entry, and admits exactly the named operations the token's roles name — that is the
// tool boundary, and no key of the gateway's is stored anywhere in this process. The
// model route speaks the OpenAI chat format; tools are plain HTTP calls through the
// same gate with the same token, and a tool the roles do not admit is refused at the
// gate and reaches the model back as a tool error, never as a crash. Three
// local-model realities it handles that a cloud demo can skip: a thinking model
// answers with empty content beside reasoning_content (that is not a failure — the
// answer or the next tool call carries the signal), completion budgets need room for
// the reasoning (~800 tokens), and a CPU-bound model needs generous timeouts. Env:
// GatewayUrl, Model, TimeoutSeconds, and AGENT_TOKEN (offline demo: a token the stub
// issuer signed) or AGENT_TENANT_ID / AGENT_CLIENT_ID / AGENT_CLIENT_SECRET /
// AGENT_API_SCOPE (live Entra grant). stdout protocol for the smokes: [reasoning],
// [tool <name> -> ...], [answer] <text>; nonzero exit only for real failure.
var gateway = Environment.GetEnvironmentVariable("GatewayUrl") ?? "http://localhost:5107";
var bearer = Environment.GetEnvironmentVariable("AGENT_TOKEN") ?? await AcquireEntraTokenAsync();
if (bearer is null)
{
    Console.WriteLine("agent: no Entra token — set AGENT_TOKEN, or AGENT_TENANT_ID, AGENT_CLIENT_ID, AGENT_CLIENT_SECRET and AGENT_API_SCOPE.");
    return 2;
}
var model = Environment.GetEnvironmentVariable("Model") ?? "qwen3-4b-generic-cpu:3";
var timeout = TimeSpan.FromSeconds(int.Parse(Environment.GetEnvironmentVariable("TimeoutSeconds") ?? "120"));
const int MaxTurns = 4;

using var http = new HttpClient { BaseAddress = new Uri(gateway), Timeout = timeout };
http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + bearer);

var messages = new JsonArray
{
    new JsonObject
    {
        ["role"] = "user",
        ["content"] = "Use the docs tool and answer with what it returns.",
    },
};
var tools = new JsonArray
{
    new JsonObject
    {
        ["type"] = "function",
        ["function"] = new JsonObject
        {
            ["name"] = "docs_lookup",
            ["description"] = "Look up the reference document.",
            ["parameters"] = new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() },
        },
    },
    new JsonObject
    {
        ["type"] = "function",
        ["function"] = new JsonObject
        {
            ["name"] = "admin_reset",
            ["description"] = "Reset the tool server (normally not allowed).",
            ["parameters"] = new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() },
        },
    },
};

for (var turn = 0; turn < MaxTurns; turn++)
{
    // Fresh detached copies go into each request: a JsonNode can have only one
    // parent, and the conversation array outlives every single request built from it.
    var request = new JsonObject
    {
        ["model"] = model,
        // A thinking model spends much of this on reasoning_content before it acts
        // or answers; a small budget truncates the reasoning and the call degrades.
        ["max_tokens"] = 800,
        ["messages"] = JsonNode.Parse(messages.ToJsonString()),
        ["tools"] = JsonNode.Parse(tools.ToJsonString()),
    };
    using var content = new StringContent(request.ToJsonString(), Encoding.UTF8, "application/json");
    using var response = await http.PostAsync("/gateway/v1/chat/completions", content);
    var responseText = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($"[error] model route refused: {(int)response.StatusCode}");
        return 4;
    }

    using var parsed = JsonDocument.Parse(responseText);
    var message = parsed.RootElement.GetProperty("choices")[0].GetProperty("message");

    // Empty content beside reasoning_content is the thinking shape, not a failure:
    // note it, then let the tool call or the next turn carry the signal.
    var answerText = message.TryGetProperty("content", out var c) ? c.GetString() : null;
    var hasReasoning = message.TryGetProperty("reasoning_content", out var r)
        && !string.IsNullOrEmpty(r.GetString());
    if (hasReasoning)
    {
        Console.WriteLine("[reasoning]");
    }

    if (!message.TryGetProperty("tool_calls", out var toolCalls) || toolCalls.GetArrayLength() == 0)
    {
        if (string.IsNullOrEmpty(answerText))
        {
            Console.WriteLine("[error] model finished with no content and no reasoning");
            return 5;
        }
        Console.WriteLine($"[answer] {answerText}");
        return 0;
    }

    // Echo the assistant turn as-is (the API contract: tool messages must follow the
    // assistant turn that named them), then execute every requested tool.
    messages.Add(JsonNode.Parse(message.GetRawText()));
    foreach (var call in toolCalls.EnumerateArray())
    {
        var id = call.GetProperty("id").GetString()!;
        var name = call.GetProperty("function").GetProperty("name").GetString()!;
        var (outcome, resultJson) = await RunToolAsync(name);
        Console.WriteLine($"[tool {name} -> {outcome}]");
        messages.Add(new JsonObject
        {
            ["role"] = "tool",
            ["tool_call_id"] = id,
            ["content"] = resultJson,
        });
    }
}

Console.WriteLine("[error] turn budget exhausted");
return 3;

async Task<(string Outcome, string Result)> RunToolAsync(string name)
{
    // Tool names to paths: the boundary under test is the caller's Operations list,
    // so both tools are addressed; only the named one passes the gate.
    var path = name switch
    {
        "docs_lookup" => "/tools/v1/docs/lookup",
        "admin_reset" => "/tools/v1/admin/reset",
        _ => null,
    };
    if (path is null)
    {
        return ("unknown-tool", """{"error":"unknown tool"}""");
    }
    try
    {
        using var response = await http.GetAsync(path);
        if (!response.IsSuccessStatusCode)
        {
            // A gate refusal is a tool error the model can read and route around —
            // the agent reports it and keeps its conversation intact.
            return ($"gateway_refused {(int)response.StatusCode}",
                $$"""{"gateway_refused":{{(int)response.StatusCode}}}""");
        }
        return ("ok", await response.Content.ReadAsStringAsync());
    }
    catch (HttpRequestException)
    {
        return ("transport-error", """{"error":"tool call failed"}""");
    }
}

// The live token path, exactly as the AgentTokens sample runs it: Entra's v2
// client-credentials grant over raw HttpClient — the agent authenticates with its own
// app's secret, never a key of the gateway's. (On Azure you would use
// DefaultAzureCredential; same token, fewer lines.) Offline runs skip this: the smoke
// fixture mints a short-lived token against the local stub issuer and passes it as
// AGENT_TOKEN.
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
