using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Core;
using Arcus.Security.Tests.Unit.KeyVault.Doubles;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Rest;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Azure.Core;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_WithoutTokenCredential_Throws()
        {
            // Arrange
            var config = Mock.Of<IKeyVaultConfiguration>();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => new KeyVaultSecretProvider(tokenCredential: null, vaultConfiguration: config));
        }

        [Fact]
        public void KeyVaultSecretProvider_WithTokenCredentialWithoutVaultConfiguration_Throws()
        {
            // Arrange
            var authentication = Mock.Of<TokenCredential>();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => new KeyVaultSecretProvider(authentication, vaultConfiguration: null));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithEmptyUri_ShouldFailWithUriFormatException()
        {
            // Arrange
            string uri = String.Empty;

            // Act & Assert
            Assert.ThrowsAny<UriFormatException>(() => new KeyVaultSecretProvider(new AzureKeyVaultAuthenticatorDummy(), new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutCorrectVaultUriSuffix_ShouldFailWithFormatException()
        {
            Assert.ThrowsAny<UriFormatException>(
                () => new KeyVaultSecretProvider(
                    new AzureKeyVaultAuthenticatorDummy(), 
                    new KeyVaultConfiguration("https://something-without-vault-azure-net-suffix")));
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
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(authentication: null, new KeyVaultConfiguration(uri)));
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
        public async Task KeyVaultSecretProvider_GetsRawSecretAsync_AfterRetriedTooManyRequestException()
        {
            // Arrange
            string expected = $"secret-value-{Guid.NewGuid()}";
            string secretName = $"secret-name-{Guid.NewGuid()}";
            KeyVaultSecretProvider provider = CreateSecretProviderWithTooManyRequestSimulation(expected);

            // Act
            string actual = await provider.GetRawSecretAsync(secretName);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetsSecretAsync_AfterRetriedTooManyRequestException()
        {
            // Arrange
            string expected = $"secret-value-{Guid.NewGuid()}";
            string secretName = $"secret-name-{Guid.NewGuid()}";
            DateTime expirationDate = DateTime.UtcNow;
            KeyVaultSecretProvider provider = CreateSecretProviderWithTooManyRequestSimulation(expected, expirationDate);

            // Act
            Secret actual = await provider.GetSecretAsync(secretName);

            // Assert
            Assert.NotNull(actual);
            Assert.Equal(expected, actual.Value);
            Assert.NotNull(actual.Version);
            Assert.Equal(expirationDate, actual.Expires);
        }

        private static KeyVaultSecretProvider CreateSecretProviderWithTooManyRequestSimulation(string expected, DateTime? expirationDate = null)
        {
            // Arrange
            var keyVaultClient = new SimulatedKeyVaultClient(
                () => throw new KeyVaultErrorException("Sabotage secret retrieval with TooManyRequests")
                {
                    Response = new HttpResponseMessageWrapper(
                        new HttpResponseMessage(HttpStatusCode.TooManyRequests),
                        "some HTTP response content to ignore")
                },
                () => new SecretBundle(
                    value: expected, 
                    id: $"http://requires-3-or-4-segments/secrets/with-the-second-named-secrets-{Guid.NewGuid()}",
                    attributes: new SecretAttributes(expires: expirationDate)));


            var provider = new KeyVaultSecretProvider(
                new StubKeyVaultAuthenticator(keyVaultClient),
                new KeyVaultConfiguration(GenerateVaultUri()));

            return provider;
        }

        private static string GenerateVaultUri()
        {
            return $"https://{Guid.NewGuid().ToString("N").Substring(0, 24)}.vault.azure.net/";
        }
    }
}
