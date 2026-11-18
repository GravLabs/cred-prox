# The vendor stand-in behind the PerCallerCredentials example — a plain ASP.NET app, no
# CredProx packages. Build context is the repository root:
#   docker build -f samples/PerCallerCredentials/StubApi/Dockerfile .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY build/Version.props build/
COPY samples/PerCallerCredentials/StubApi samples/PerCallerCredentials/StubApi
RUN dotnet publish samples/PerCallerCredentials/StubApi -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app /app
ENTRYPOINT ["dotnet", "/app/StubApi.dll"]
