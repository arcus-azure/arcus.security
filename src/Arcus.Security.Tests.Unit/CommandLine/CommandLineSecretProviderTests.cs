using System;
using Arcus.Security.Providers.CommandLine;
using Xunit;

namespace Arcus.Security.Tests.Unit.CommandLine
{
    public class CommandLineSecretProviderTests
    {
        [Fact]
        public void CreateProvider_WithoutConfigurationProvider_Fails()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new CommandLineSecretProvider(configurationProvider: null));
        }
    }
}
