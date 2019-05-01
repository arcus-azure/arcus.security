using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
#pragma warning disable 618

namespace Arcus.Security.Secrets.AzureKeyVault
{
    /// <summary>
    ///     Proxy compatible implementation to make the migration towards the <see cref="IKeyVaultAuthentication"/> backwards compatible.
    /// </summary>
    /// <remarks>
    ///     Can be deleted when the <see cref="IKeyVaultAuthenticator"/> is removed.
    /// </remarks>
    internal class CompatibleKeyVaultAuthentication : IKeyVaultAuthentication
    {
        private readonly IKeyVaultAuthenticator _authenticator;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompatibleKeyVaultAuthentication"/> class.
        /// </summary>
        /// <param name="authenticator">The requested authentication type for connecting to the Azure Key Vault instance</param>
        internal CompatibleKeyVaultAuthentication(IKeyVaultAuthenticator authenticator)
        {
            Guard.NotNull(authenticator, nameof(authenticator));
            
            _authenticator = authenticator;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        public async Task<IKeyVaultClient> Authenticate()
        {
            return await _authenticator.Authenticate();
        }
    }
}
