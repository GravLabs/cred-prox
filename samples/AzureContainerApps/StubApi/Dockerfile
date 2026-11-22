# The vendor stand-in image for the ACA live run: the shipped StubApi, unchanged.
# Deployed as the co-located second container of the Container App
# (infra/azure/aca-m46-app.yaml.tmpl) so the sample's shipped
# http://localhost:8098 destination is served inside the same pod. No CredProx
# reference, no feed, no credential ever lives here - it only echoes what the
# gateway forwards and hands the raw header to /__last-auth.
# Build context is the repository root:
#   docker build -f samples/AzureContainerApps/StubApi/Dockerfile -t credprox-m46-stub:latest .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY build/Version.props build/
COPY samples/AzureContainerApps/StubApi samples/AzureContainerApps/StubApi
RUN dotnet publish samples/AzureContainerApps/StubApi -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app /app
ENTRYPOINT ["dotnet", "/app/StubApi.dll"]
