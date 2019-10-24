using Arcus.Security.Providers.AzureKeyVault.Authentication;
using System;
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
            var authenticator = new ServicePrincipalAuthentication(clientId: clientId, clientKey: clientKey);

            // Assert
            Assert.NotNull(authenticator);
        }

        [Fact]
        public void Constructor_ClientIdNotSpecified_ThrowsArgumentException()
        {
            // Arrange
            string clientKey = Guid.NewGuid().ToString();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ServicePrincipalAuthentication(clientId: null, clientKey: clientKey));
        }

        [Fact]
        public void Constructor_ClientKeyNotSpecified_ThrowsArgumentException()
        {
            // Arrange
            string clientId = Guid.NewGuid().ToString();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ServicePrincipalAuthentication(clientId: clientId, clientKey: null));
        }
    }
}
