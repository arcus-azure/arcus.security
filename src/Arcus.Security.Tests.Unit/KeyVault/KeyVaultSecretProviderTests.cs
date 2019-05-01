using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Secrets.AzureKeyVault;
using Arcus.Security.Tests.Unit.KeyVault.Doubles;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Rest;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_CreateWithEmptyUri_ShouldFailWithUriFormatException()
        {
            // Arrange
            string uri = string.Empty;

            // Act & Assert
            Assert.ThrowsAny<UriFormatException>(() => new KeyVaultSecretProvider(new AzureKeyVaultAuthenticatorDummy(), new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithHttpScheme_ShouldFailWithUriFormatException()
        {
            // Arrange
            string uri = $"http://{Guid.NewGuid():N}.vault.azure.net/";

            // Act & Assert
            Assert.ThrowsAny<UriFormatException>(() => new KeyVaultSecretProvider((IKeyVaultAuthentication) null, new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutUri_ShouldFailWithArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(
                () => new KeyVaultSecretProvider(
                    new AzureKeyVaultAuthenticatorDummy(), 
                    new KeyVaultConfiguration(rawVaultUri: null)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutClientFactory_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = GenerateVaultUri();

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider((IKeyVaultAuthentication) null, new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithValidArguments_ShouldSucceed()
        {
            // Arrange
            string uri = GenerateVaultUri();

            // Act & Assert
            var secretProvider = new KeyVaultSecretProvider(new AzureKeyVaultAuthenticatorDummy(), new KeyVaultConfiguration(uri));
            Assert.NotNull(secretProvider);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetsSecretValue_AfterRetriedTooManyRequestException()
        {
            // Arrange
            string secretName = $"secret-name-{Guid.NewGuid()}";
            string expected = $"secret-value-{Guid.NewGuid()}";

            var keyVaultClient = new SimulatedKeyVaultClient(
                request => throw new KeyVaultErrorException("Sabotage secret retrieval with TooManyRequests")
                {
                    Response = new HttpResponseMessageWrapper(
                        new HttpResponseMessage(HttpStatusCode.TooManyRequests), 
                        "some HTTP response content to ignore")
                },
                request => new SecretBundle(value: expected));


            var provider = new KeyVaultSecretProvider(
                new StubKeyVaultAuthenticator(keyVaultClient), 
                new KeyVaultConfiguration(GenerateVaultUri()));

            // Act
            string actual = await provider.Get(secretName);

            // Assert
            Assert.Equal(expected, actual);
        }

        private static string GenerateVaultUri()
        {
            return $"https://{Guid.NewGuid():N}.vault.azure.net/";
        }
    }
}
