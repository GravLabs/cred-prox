# The stand-in downstream behind the TokenExchange example — a plain ASP.NET app, no
# CredProx packages. Build context is the repository root:
#   docker build -f samples/TokenExchange/StubApi/Dockerfile .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY build/Version.props build/
COPY samples/TokenExchange/StubApi samples/TokenExchange/StubApi
RUN dotnet publish samples/TokenExchange/StubApi -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app /app
ENTRYPOINT ["dotnet", "/app/StubApi.dll"]
