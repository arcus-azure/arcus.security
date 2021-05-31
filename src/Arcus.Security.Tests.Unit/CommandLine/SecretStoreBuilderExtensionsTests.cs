using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.CommandLine
{
    public class SecretStoreBuilderExtensionsTests
    {
        [Fact]
        public async Task AddCommandLine_WithArguments_Succeeds()
        {
            // Arrange
            string secretName = "MySecret", expected = "P@ssw0rd";
            var arguments = new[] {$"--{secretName}={expected}"};
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddCommandLine(arguments));

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                string actual = await provider.GetRawSecretAsync(secretName);
                
                Assert.Equal(expected, actual);
            }
        }
        
        [Fact]
        public void AddCommandLine_WithoutArguments_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddCommandLine(arguments: null));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddCommandLine_WithNameWithoutArguments_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddCommandLine(arguments: null, name: "Command line"));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddCommandLine_WithMutateSecretWithoutArguments_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCommandLine(arguments: null, mutateSecretName: secretName => secretName);
            });
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddCommandLine_WithNameWithMutateSecretWithoutArguments_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCommandLine(
                    arguments: null,
                    name: "Command line",
                    mutateSecretName: secretName => secretName);
            });
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
