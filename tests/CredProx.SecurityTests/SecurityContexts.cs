using System.Text;
using CredProx;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace CredProx.SecurityTests;

/// <summary>
/// A real <see cref="HttpContext"/> carrying the features the M4 request features read —
/// built only from CredProx's public surface, so the security properties hold for what a
/// consumer actually gets, not for test-internal shapes.
/// </summary>
internal static class SecurityContexts
{
    public static DefaultHttpContext Create(
        out HttpRequestMessage proxyRequest,
        string? destinationName)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("caller");
        context.Request.Path = "/api";

        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = "route-1",
                Metadata = destinationName is null
                    ? null
                    : new Dictionary<string, string> { [CredProxMetadata.Destination] = destinationName },
            },
            cluster: null,
            HttpTransformer.Default);
        var cluster = new ClusterModel(
            new ClusterConfig { ClusterId = "cluster-1" },
            new HttpMessageInvoker(new SocketsHttpHandler()));
        context.Features.Set<IReverseProxyFeature>(new StubReverseProxyFeature(route, cluster));

        proxyRequest = new HttpRequestMessage(HttpMethod.Get, "http://upstream/api");
        context.Features.Set(new CredProxRequestState(context, proxyRequest));
        context.Response.Body = new MemoryStream();
        return context;
    }

    public static string ResponseBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEnd();
    }

    private sealed class StubReverseProxyFeature(RouteModel route, ClusterModel cluster) : IReverseProxyFeature
    {
        public RouteModel Route { get; } = route;

        public ClusterModel Cluster { get; } = cluster;

        public IReadOnlyList<DestinationState> AllDestinations { get; } = [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }
}
