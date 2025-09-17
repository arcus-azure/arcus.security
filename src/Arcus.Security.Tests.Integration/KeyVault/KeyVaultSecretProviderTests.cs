using System.Linq;
using Arcus.Security.Core;
using Arcus.Security.Tests.Integration.KeyVault.Fixture;
using Arcus.Testing;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public partial class KeyVaultSecretProviderTests : IntegrationTest
    {
        public KeyVaultSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        private string TenantId => Configuration.GetTenantId();
        private string ClientId => Configuration.GetServicePrincipalClientId();
        private string ClientSecret => Configuration.GetServicePrincipalClientSecret();
        private string VaultUri => $"https://{Configuration.GetRequiredValue("Arcus:KeyVault:Name")}.vault.azure.net/";
        private string TestSecretName => Configuration.GetSecretName();
        private string TestSecretValue => Configuration.GetSecretValue();
        private string TestSecretVersion => Configuration.GetSecretVersion();

        private TemporaryManagedIdentityConnection UseTemporaryManagedIdentityConnection()
        {
            return TemporaryManagedIdentityConnection.Create(TenantId, ClientId, ClientSecret);
        }

        private void AssertTrackedAzureKeyVaultDependency(int expectedTrackedDependencyCount)
        {
            int actualTrackedDependencyCount = InMemoryLogSink.CurrentLogEmits.Count(ev => ev.MessageTemplate.Text.Contains("Dependency"));

            Assert.Equal(expectedTrackedDependencyCount, actualTrackedDependencyCount);
        }

        private void AssertSecret(Secret secret)
        {
            Assert.NotNull(secret);
            AssertSecretValue(secret.Value);
            Assert.NotNull(secret.Version);
        }

        private void AssertSecretValue(string secretValue)
        {
            Assert.Equal(TestSecretValue, secretValue);
        }
    }
}
