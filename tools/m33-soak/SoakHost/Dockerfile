# M33 soak host image (plan §5.5). Publish happens on the HOST (its NuGet cache carries the
# Azure provider closure; the container build stays a runtime-only copy so the image is
# byte-stable and fast to rebuild):
#   dotnet publish tools/m33-soak/SoakHost -c Release -o tools/m33-soak/build/publish
#   docker build -f tools/m33-soak/SoakHost/Dockerfile -t credprox-soakhost:local .
FROM mcr.microsoft.com/dotnet/aspnet@sha256:aa89a25c13f60a1df1018742e6e7fecd8d93cba469f3d079de410ff1390634ac
WORKDIR /app
COPY tools/m33-soak/build/publish/ ./
ENV SOAK_STATS_PATH=/soak/stats.csv
EXPOSE 8080
ENTRYPOINT ["dotnet", "SoakHost.dll"]
