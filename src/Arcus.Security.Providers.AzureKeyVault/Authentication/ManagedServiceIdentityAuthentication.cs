using System;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Azure Key Vault authentication by using Azure Managed Service Identity
    /// </summary>
    public class ManagedServiceIdentityAuthentication : IKeyVaultAuthentication
    {
        private readonly string _connectionString;
        private readonly string _azureAdInstance;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ManagedServiceIdentityAuthentication"/> class.
        /// </summary>
        public ManagedServiceIdentityAuthentication()
            : this(NullLogger<ManagedServiceIdentityAuthentication>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ManagedServiceIdentityAuthentication"/> class.
        /// </summary>
        /// <param name="logger">The logger to write diagnostic trace messages during authenticating with the Azure Key Vault, if applicable.</param>
        public ManagedServiceIdentityAuthentication(ILogger<ManagedServiceIdentityAuthentication> logger)
            : this(connectionString: null, azureAdInstance: null, logger: logger)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ManagedServiceIdentityAuthentication"/> class.
        /// </summary>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureAdInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="logger">The logger to write diagnostic trace messages during authenticating with the Azure Key Vault, if applicable.</param>
        public ManagedServiceIdentityAuthentication(
            string connectionString = null, 
            string azureAdInstance = null, 
            ILogger<ManagedServiceIdentityAuthentication> logger = null)
        {
            _connectionString = connectionString;
            _azureAdInstance = azureAdInstance;
            _logger = logger ?? NullLogger<ManagedServiceIdentityAuthentication>.Instance;
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            _logger.LogTrace("Start authenticating with managed service identity to the Azure Key Vault...");
            IKeyVaultClient keyVaultClient = AuthenticateClient();
            _logger.LogInformation("Authenticated with managed service identity to the Azure Key Vault");

            return Task.FromResult(keyVaultClient);
        }

        private KeyVaultClient AuthenticateClient()
        {
            try
            {
                // Unfortunately the default azureAdInstance is hardcoded to a value rather than null, avoid having to hard code the value here too.
                AzureServiceTokenProvider tokenProvider =
                    _azureAdInstance is null
                        ? new AzureServiceTokenProvider(_connectionString)
                        : new AzureServiceTokenProvider(_connectionString, _azureAdInstance);

                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
                var keyVaultClient = new KeyVaultClient(authenticationCallback);

                return keyVaultClient;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Failure during authenticating with managed service identity to the Azure Key Vault");
                throw;
            }
        }
    }
}
