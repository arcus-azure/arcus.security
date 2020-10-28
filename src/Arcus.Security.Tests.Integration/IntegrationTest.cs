using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Testing.Logging;
using Microsoft.Extensions.Configuration;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration
{
    public class IntegrationTest
    {
        protected TestConfig Configuration { get; }
        protected XunitTestLogger Logger { get; }

        public IntegrationTest(ITestOutputHelper testOutput)
        {
            Logger = new XunitTestLogger(testOutput);

            // The appsettings.local.json allows users to override (gitignored) settings locally for testing purposes
            Configuration = TestConfig.Create();
        }
    }
}