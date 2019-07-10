using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Azure Key Vault <see cref="IKeyVaultAuthentication"/> by using client ID and certificate to authenticate the <see cref="IKeyVaultClient"/>.
    /// </summary>
    public class CertificateBasedAuthentication : IKeyVaultAuthentication
    {
        private readonly string _clientId;
        private readonly X509Certificate2 _certificate;

        /// <summary>
        ///     Initializes a new instance of the <see cref="CertificateBasedAuthentication"/> class.
        /// </summary>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        public CertificateBasedAuthentication(string clientId, X509Certificate2 certificate)
        {
            Guard.NotNull(clientId, nameof(clientId));
            Guard.NotNull(certificate, nameof(certificate));

            _clientId = clientId;
            _certificate = certificate;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        [Obsolete("Use the " + nameof(AuthenticateAsync) + " method instead")]
        public Task<IKeyVaultClient> Authenticate()
        {
            return AuthenticateAsync();
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            try
            {
                IKeyVaultClient client = new KeyVaultClient(AuthenticationCallbackAsync);
                return Task.FromResult(client);
            }
            catch (Exception ex)
            {
                return Task.FromException<IKeyVaultClient>(ex);
            }
        }

        private async Task<string> AuthenticationCallbackAsync(string authority, string resource, string scope)
        {
            var authenticationContext = new AuthenticationContext(authority);
            var clientAssertionCertificate = new ClientAssertionCertificate(_clientId, _certificate);

            AuthenticationResult result = await authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate);
            return result.AccessToken;
        }
    }
}
