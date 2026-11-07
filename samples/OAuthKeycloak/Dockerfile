# Build context is the repository root (the example consumes the packed CredProx packages
# from artifacts/packages — pack before building):
#   docker build -f samples/OAuthKeycloak/Dockerfile .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY samples/nuget.config samples/nuget.config
COPY samples/OAuthKeycloak samples/OAuthKeycloak
COPY artifacts/packages artifacts/packages
RUN dotnet publish samples/OAuthKeycloak -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app /app
ENTRYPOINT ["dotnet", "/app/OAuthKeycloak.dll"]
