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
        private readonly string _applicationId;
        private readonly X509Certificate2 _certificate;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBasedAuthentication"/> class.
        /// </summary>
        /// <param name="applicationId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        public CertificateBasedAuthentication(string applicationId, X509Certificate2 certificate)
        {
            Guard.NotNull(applicationId, nameof(applicationId));
            Guard.NotNull(certificate, nameof(certificate));

            _applicationId = applicationId;
            _certificate = certificate;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> Authenticate()
        {
            IKeyVaultClient client = new KeyVaultClient((async (authority, resource, scope) =>
            {
                var authenticationContext = new AuthenticationContext(authority);
                var clientAssertionCertificate = new ClientAssertionCertificate(_applicationId, _certificate);
                
                AuthenticationResult result = await authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate);
                return result.AccessToken;
            }));

            return Task.FromResult(client);
        }
    }
}
