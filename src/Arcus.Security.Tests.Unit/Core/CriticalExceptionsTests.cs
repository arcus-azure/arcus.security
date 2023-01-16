using System;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CriticalExceptionsTests
    {
        [Fact]
        public async Task GetSecret_WithThrownCriticalException_FailsWithCriticalException()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(new SaboteurSecretProvider(new IOException("Something happened!")))
                      .AddCriticalException<IOException>();
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Throws<IOException>(() => secretProvider.GetSecret("Some.Secret"));
            Assert.Throws<IOException>(() => secretProvider.GetRawSecret("Some.Secret"));
            await Assert.ThrowsAsync<IOException>(() => secretProvider.GetSecretAsync("Some.Secret"));
            await Assert.ThrowsAsync<IOException>(() => secretProvider.GetRawSecretAsync("Some.Secret"));
        }

        [Fact]
        public async Task GetSecret_WithThrownNonCriticalException_FailsWithSecretNotFoundException()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(new SaboteurSecretProvider(new AccessViolationException("Something happened!")))
                      .AddCriticalException<IOException>();
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret("Some.Secret"));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret("Some.Secret"));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync("Some.Secret"));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync("Some.Secret"));
        }
    }
}
