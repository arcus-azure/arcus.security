using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Tests.Runtimes.AzureFunctions
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host =
                Host.CreateDefaultBuilder(args)
                    .ConfigureFunctionsWorkerDefaults()
                    .ConfigureAppConfiguration(config => config.AddInMemoryCollection(new[]
                    {
                        new KeyValuePair<string, string>("ArcusTestSecret", "TestSecret")
                    }))
                    .ConfigureSecretStore((config, stores) => stores.AddConfiguration(config))
                    .Build();

            host.Run();
        }
    }
}
