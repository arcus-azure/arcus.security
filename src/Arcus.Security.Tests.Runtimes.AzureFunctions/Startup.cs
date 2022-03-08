using System.Collections.Generic;
using Arcus.Security.Tests.Runtimes.AzureFunctions;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

[assembly: FunctionsStartup(typeof(Startup))]

namespace Arcus.Security.Tests.Runtimes.AzureFunctions
{
    public class Startup : FunctionsStartup
    {
        // This method gets called by the runtime. Use this method to configure the app configuration.
        public override void ConfigureAppConfiguration(IFunctionsConfigurationBuilder builder)
        {
            builder.ConfigurationBuilder.AddInMemoryCollection(new[]
            {
                new KeyValuePair<string, string>("ArcusTestSecret", "TestSecret")
            });
        }
        
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://docs.microsoft.com/en-us/azure/azure-functions/functions-dotnet-dependency-injection
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.ConfigureSecretStore((context, config, stores) =>
            {
                stores.AddConfiguration(config);
            });
        }
    }
}
