# ACA deployment image: one host, no modes — every fact comes from config and env.
# Build context is the repository root (the host consumes the packed CredProx packages
# from artifacts/packages - pack before building):
#   dotnet pack src/CredProx -c Release -o artifacts/packages
#   dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/packages
#   dotnet pack src/CredProx.CallerKeys -c Release -o artifacts/packages
#   docker build -f samples/AzureContainerApps/Dockerfile -t credprox-aca:latest .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY build/Version.props build/
COPY samples/nuget.config samples/nuget.config
COPY samples/AzureContainerApps samples/AzureContainerApps
COPY artifacts/packages artifacts/packages
RUN dotnet publish samples/AzureContainerApps -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app /app
# Container Apps sends ingress traffic to the target port (README deploy step 4).
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/AzureContainerApps.dll"]
