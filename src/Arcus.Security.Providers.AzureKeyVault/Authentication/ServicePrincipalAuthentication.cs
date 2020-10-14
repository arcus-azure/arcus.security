using System;
using System.Security.Authentication;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    /// Representation of an <see cref="IKeyVaultAuthentication"/> that will generate a <see cref="IKeyVaultClient"/> implementation using a service principle.
    /// </summary>
    public class ServicePrincipalAuthentication : IKeyVaultAuthentication
    {
        private readonly string _clientId;
        private readonly string _clientKey;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes <see cref="ServicePrincipalAuthentication"/> that will generate a KeyVaultClient, using a service principal
        /// </summary>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <exception cref="ArgumentException">When the <paramref name="clientId"/> is <c>null</c> or empty.</exception>
        /// <exception cref="ArgumentException">When the <paramref name="clientKey"/> is <c>null</c> or empty.</exception>
        public ServicePrincipalAuthentication(string clientId, string clientKey)
            : this(clientId, clientKey, NullLogger<ServicePrincipalAuthentication>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ServicePrincipalAuthentication"/> class.
        /// </summary>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="logger">The logger to write diagnostic trace messages during authenticating with Azure Key Vault.</param>
        /// <exception cref="ArgumentException">When the <paramref name="clientId"/> is <c>null</c> or empty.</exception>
        /// <exception cref="ArgumentException">When the <paramref name="clientKey"/> is <c>null</c> or empty.</exception>
        public ServicePrincipalAuthentication(string clientId, string clientKey, ILogger<ServicePrincipalAuthentication> logger)
        {
            Guard.NotNullOrEmpty(clientId, nameof(clientId), "Requires an client ID of the service principal to authenticate with the Azure Key Vault");
            Guard.NotNullOrEmpty(clientKey, nameof(clientKey), "Requires a client secret key of the service principal to authenticate with the Azure Key Vault");

            _clientId = clientId;
            _clientKey = clientKey;
            _logger = logger ?? NullLogger<ServicePrincipalAuthentication>.Instance;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        /// <exception cref="InvalidOperationException">When the JSON web token (JWT) cannot be obtained.</exception>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            _logger.LogTrace("Start authenticating with service principal to Azure Key Vault...");
            IKeyVaultClient keyVaultClient = new KeyVaultClient(GetTokenAsync);
            _logger.LogInformation("Authenticated with service principal to Azure Key Vault");

            return Task.FromResult(keyVaultClient);
        }

        private async Task<string> GetTokenAsync(string authority, string resource, string scope)
        {
            AuthenticationResult result;

            try
            {
                var authContext = new AuthenticationContext(authority);
                var clientCred = new ClientCredential(_clientId, _clientKey);

                result = await authContext.AcquireTokenAsync(resource, clientCred);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Failure during authentication to Azure Key Vault");
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
