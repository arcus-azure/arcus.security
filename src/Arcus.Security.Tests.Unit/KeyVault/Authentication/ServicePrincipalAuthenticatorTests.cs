using System;
using System.Collections.Generic;
using System.Text;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault.Authentication
{
    public class ServicePrincipalAuthenticatorTests
    {
        [Fact]
        public void Constructor_ValidArguments_Succeeds()
        {
            // Arrange
            string clientId = Guid.NewGuid().ToString();
            string clientKey = Guid.NewGuid().ToString();

            // Act
            var authenticator = new ServicePrincipalAuthenticator(clientId: clientId, clientKey: clientKey);

            // Assert
            Assert.NotNull(authenticator);
        }

        [Fact]
        public void Constructor_ClientIdNotSpecified_ThrowsArgumentException()
        {
            // Arrange
            string clientKey = Guid.NewGuid().ToString();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ServicePrincipalAuthenticator(clientId: null, clientKey: clientKey));
        }

        [Fact]
        public void Constructor_ClientKeyNotSpecified_ThrowsArgumentException()
        {
            // Arrange
            string clientId = Guid.NewGuid().ToString();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ServicePrincipalAuthenticator(clientId: clientId, clientKey: null));
        }
    }
}
