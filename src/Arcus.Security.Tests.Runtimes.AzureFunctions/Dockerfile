FROM mcr.microsoft.com/azure-functions/dotnet:4 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0.100-bullseye-slim AS build
WORKDIR /src
COPY ["Arcus.Security.Tests.Runtimes.AzureFunctions/Arcus.Security.Tests.Runtimes.AzureFunctions.csproj", "Arcus.Security.Tests.Runtimes.AzureFunctions"]

COPY . .
WORKDIR "/src/Arcus.Security.Tests.Runtimes.AzureFunctions"
RUN dotnet build "Arcus.Security.Tests.Runtimes.AzureFunctions.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "Arcus.Security.Tests.Runtimes.AzureFunctions.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENV AzureWebJobsScriptRoot=/app \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true