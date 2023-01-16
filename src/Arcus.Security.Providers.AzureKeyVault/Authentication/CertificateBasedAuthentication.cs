using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Identity;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Azure Key Vault <see cref="IKeyVaultAuthentication"/> by using client ID and certificate to authenticate the <see cref="IKeyVaultClient"/>.
    /// </summary>
    [Obsolete("Azure Key Vault authentication is moved to Azure Identity approach where the certificate authentication becomes: " + nameof(ClientCertificateCredential))]
    [ExcludeFromCodeCoverage]
    public class CertificateBasedAuthentication : IKeyVaultAuthentication
    {
        private readonly string _clientId;
        private readonly X509Certificate2 _certificate;
        private readonly ILogger _logger;

        /// <summary>
        ///     Initializes a new instance of the <see cref="CertificateBasedAuthentication"/> class.
        /// </summary>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <exception cref="ArgumentNullException">When the <paramref name="clientId"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">When the <paramref name="certificate"/> is <c>null</c>.</exception>
        public CertificateBasedAuthentication(string clientId, X509Certificate2 certificate)
            : this(clientId, certificate, NullLogger<CertificateBasedAuthentication>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateBasedAuthentication"/> class.
        /// </summary>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="logger">The logger to write diagnostic trace messages during authenticating with the Azure Key vault.</param>
        /// <exception cref="ArgumentNullException">When the <paramref name="clientId"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">When the <paramref name="certificate"/> is <c>null</c>.</exception>
        public CertificateBasedAuthentication(string clientId, X509Certificate2 certificate, ILogger<CertificateBasedAuthentication> logger)
        {
            Guard.NotNull(clientId, nameof(clientId), "Requires an client ID of the application to authenticate with the Azure Key Vault");
            Guard.NotNull(certificate, nameof(certificate), "Requires a credential certificate of the application to authenticate with the Azure Key Vault");

            _clientId = clientId;
            _certificate = certificate;
            _logger = logger ?? NullLogger<CertificateBasedAuthentication>.Instance;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            _logger.LogTrace("Start authenticating with certificate to the Azure Key Vault...");
            IKeyVaultClient client = new KeyVaultClient(AuthenticationCallbackAsync);
            _logger.LogTrace("Authenticated with certificate to the Azure Key Vault");

            return Task.FromResult(client);
        }

        private async Task<string> AuthenticationCallbackAsync(string authority, string resource, string scope)
        {
            AuthenticationResult result;

            try
            {
                var authenticationContext = new AuthenticationContext(authority);
                var clientAssertionCertificate = new ClientAssertionCertificate(_clientId, _certificate);

                result = await authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Failure during authenticating with certificate to the Azure Key Vault");
                throw;
            }

            if (result is null)
            {
                _logger.LogError("Authenticating to Azure Key Vault failed because no JWT token could be obtained");
                throw new AuthenticationException("Failed to obtain the JWT access token");
            }

            return result.AccessToken;
        }
    }
}
