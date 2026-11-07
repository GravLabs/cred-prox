# M29 round-2 sample image: one image, three roles via --mode (proxy | counterparty |
# battery) - see Program.cs header. Build context is the repository root (the example
# consumes the packed CredProx packages from artifacts/packages - pack before building):
#   dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
#   dotnet pack src/CredProx -c Release -o artifacts/packages
#   dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/packages
#   docker build -f samples/AzureContainerApps/Dockerfile -t credprox-m29:latest .
# Offline proof (G1): docker run --rm credprox-m29:latest --mode proxy --smoke
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY samples/nuget.config samples/nuget.config
COPY samples/AzureContainerApps samples/AzureContainerApps
COPY artifacts/packages artifacts/packages
RUN dotnet publish samples/AzureContainerApps -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
# ca-certificates backs the entrypoint's trust-store install (the PUBLIC test-CA cert
# arrives via CREDPROX_TEST_CA_PEM_B64 - see entrypoint.sh and the README's honesty
# notes; secret material still arrives only from Key Vault through CredProx's provider).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app /app
COPY samples/AzureContainerApps/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
