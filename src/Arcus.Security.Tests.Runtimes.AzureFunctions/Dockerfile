#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/azure-functions/dotnet-isolated:4-dotnet-isolated8.0 AS base
WORKDIR /home/site/wwwroot
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:8.0.100-preview.7-alpine3.18 AS build
WORKDIR /src
COPY ["Arcus.Security.Tests.Runtimes.AzureFunctions/Arcus.Security.Tests.Runtimes.AzureFunctions.csproj", "Arcus.Security.Tests.Runtimes.AzureFunctions/"]
RUN dotnet restore "Arcus.Security.Tests.Runtimes.AzureFunctions/Arcus.Security.Tests.Runtimes.AzureFunctions.csproj"
COPY . .
WORKDIR "/src/Arcus.Security.Tests.Runtimes.AzureFunctions"
RUN dotnet build "Arcus.Security.Tests.Runtimes.AzureFunctions.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Arcus.Security.Tests.Runtimes.AzureFunctions.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /home/site/wwwroot
COPY --from=publish /app/publish .
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true