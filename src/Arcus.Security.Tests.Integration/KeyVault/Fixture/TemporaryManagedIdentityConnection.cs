using System;
using Arcus.Security.Tests.Core.Fixture;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault.Fixture
{
    public class TemporaryManagedIdentityConnection : IDisposable
    {
        private readonly TemporaryEnvironmentVariable[] _variables;

        private TemporaryManagedIdentityConnection(string clientId, params TemporaryEnvironmentVariable[] variables)
        {
            _variables = variables;
            ClientId = clientId;
        }

        public string ClientId { get; }

        public static TemporaryManagedIdentityConnection Create(string tenantId, string clientId, string clientSecret)
        {
            return new TemporaryManagedIdentityConnection(
                clientId,
                TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId),
                TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId),
                TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientSecret));
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Assert.All(_variables, var => var.Dispose());
        }
    }
}
