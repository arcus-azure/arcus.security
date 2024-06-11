using System.Linq;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public partial class KeyVaultSecretProviderTests : IntegrationTest
    {
        public KeyVaultSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        private string TenantId => Configuration.GetTenantId();
        private string ClientId => Configuration.GetRequiredValue("Arcus:ServicePrincipal:ApplicationId");
        private string ClientSecret => Configuration.GetRequiredValue("Arcus:ServicePrincipal:AccessKey");
        private string VaultUri => Configuration.GetRequiredValue("Arcus:KeyVault:Uri");
        private string TestSecretName => Configuration.GetSecretName();
        private string TestSecretValue => Configuration.GetSecretValue();
        private string TestSecretVersion => Configuration.GetSecretVersion();
       

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
