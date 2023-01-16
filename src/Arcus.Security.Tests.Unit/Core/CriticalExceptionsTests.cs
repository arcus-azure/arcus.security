using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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
            await Assert.ThrowsAsync<IOException>(() => secretProvider.GetSecretAsync("Some.Secret"));
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
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync("Some.Secret"));
        }
    }
}
