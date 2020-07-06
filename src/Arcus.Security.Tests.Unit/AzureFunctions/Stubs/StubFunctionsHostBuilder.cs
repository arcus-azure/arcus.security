using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace Arcus.Security.Tests.Unit.AzureFunctions.Stubs
{
    public class StubFunctionsHostBuilder : IFunctionsHostBuilder
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="StubFunctionsHostBuilder"/> class.
        /// </summary>
        public StubFunctionsHostBuilder()
        {
            Services = new ServiceCollection().AddLogging();
        }

        public IServiceCollection Services { get; }

        public IServiceProvider Build()
        {
            return Services.BuildServiceProvider();
        }
    }
}
