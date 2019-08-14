using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Tests.Unit.KeyVault.Doubles
{
    /// <summary>
    ///     Representation of an <see cref="IKeyVaultAuthentication"/> that stubs out an <see cref="IKeyVaultClient"/> implementation.
    /// </summary>
    public class StubKeyVaultAuthenticator : IKeyVaultAuthentication
    {
        private readonly IKeyVaultClient _keyVaultClient;

        /// <summary>
        ///     Initializes a new instance of the <see cref="StubKeyVaultAuthenticator"/> class.
        /// </summary>
        /// <param name="keyVaultClient">The stubbed client used to interact with the vault.</param>
        /// <exception cref="ArgumentNullException">When the <paramref name="keyVaultClient"/> is <c>null</c>.</exception>
        public StubKeyVaultAuthenticator(IKeyVaultClient keyVaultClient)
        {
            Guard.NotNull(keyVaultClient, nameof(keyVaultClient));

            _keyVaultClient = keyVaultClient;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        [Obsolete("Use the " + nameof(AuthenticateAsync) + " method instead")]
        public Task<IKeyVaultClient> Authenticate()
        {
            return Task.FromResult(_keyVaultClient);
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            return Task.FromResult(_keyVaultClient);
        }
    }
}
