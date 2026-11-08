# M31 spike container (plan 5.4): AFL++ + .NET 10 for coverage-guided fuzzing of CredProx.
# The host has no clang and must stay unmodified, so the whole
# fuzzing toolchain lives here. Base image pinned by digest; tool versions pinned.
FROM aflplusplus/aflplusplus@sha256:9b168a35bf0d5a270ed96b5017d7012805a8cedb37e40d9fea8f4e8c57200d24

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
 && bash /tmp/dotnet-install.sh --channel 10.0 --install-dir /usr/share/dotnet \
 && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
 && rm /tmp/dotnet-install.sh

# TieredCompilation off and ReadyToRun off are required for instrumentation feedback to
# be stable (documented SharpFuzz/AFL requirement); invariant globalization — the harness
# compares ordinally and needs no ICU.
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NoLogo=1 \
    DOTNET_TieredCompilation=0 \
    DOTNET_ReadyToRun=0 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

RUN dotnet tool install --global SharpFuzz.CommandLine --version 2.3.0
ENV PATH="/root/.dotnet/tools:${PATH}"
