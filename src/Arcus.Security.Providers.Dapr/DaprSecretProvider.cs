using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Observability.Telemetry.Core;
using Arcus.Security.Core;
using Dapr.Client;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Providers.Dapr
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> retrieving secrets from the Dapr secret store.
    /// </summary>
    public class DaprSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DaprSecretProvider" /> class.
        /// </summary>
        /// <param name="secretStore">The name of the Dapr secret store from which the secrets should be retrieved from.</param>
        /// <param name="options">The optional set of options to manipulate the basic behavior of how the secrets should be retrieved.</param>
        /// <param name="logger">The logger instance to write diagnostic trace messages during the retrieval of the Dapr secrets.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretStore"/> is blank.</exception>
        public DaprSecretProvider(string secretStore, DaprSecretProviderOptions options, ILogger<DaprSecretProvider> logger)
        {
            Guard.NotNullOrWhitespace(secretStore, nameof(secretStore));

            SecretStore = secretStore;
            Options = options ?? new DaprSecretProviderOptions();
            Logger = logger ?? NullLogger<DaprSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the name of the Dapr secret store for which this secret provider is configured.
        /// </summary>
        protected string SecretStore { get; }
        
        /// <summary>
        /// Gets the optional set of configured options to manipulated the basic behavior of how the secrets should be retrieved.
        /// </summary>
        /// <remarks>
        ///     Options set when configuring this secret provider in the secret store.
        /// </remarks>
        protected DaprSecretProviderOptions Options { get; }


        /// <summary>
        /// Gets the logger instance to write diagnostic trace messages during the Dapr secret retrieval.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key.</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null.</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name.</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName));

            string secretValue = await GetRawSecretAsync(secretName);
            return new Secret(secretValue);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key.</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null.</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name.</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName));

            Logger.LogTrace("Getting a secret '{SecretName}' from Dapr secret store '{StoreName}'...", secretName, SecretStore);

            (string daprSecretName, string daprSecretSection) = DetermineDaprSecretName(secretName);
            string secretValue = await GetDaprSecretValueAsync(daprSecretName, daprSecretSection);
            
            Logger.LogTrace("Got secret '{SecretName}' from from Dapr secret store '{StoreName}'", secretName, SecretStore);
            return secretValue;
        }

        /// <summary>
        /// Determine the Dapr secret key and section based on the user passed-in <paramref name="secretName"/>.
        /// </summary>
        /// <remarks>
        ///     The key of the secret in the Dapr secret store can be the same as the section for single-valued Dapr secrets, but is different in multi-valued Dapr secrets.
        ///     Therefore, make sure to split the <paramref name="secretName"/> into the required (key, section) pair for your use-case.
        /// </remarks>
        /// <param name="secretName">The user passed-in secret which gets translated to a Dapr secret key and section.</param>
        protected virtual (string daprSecretKey, string daprSecretSection) DetermineDaprSecretName(string secretName)
        {
            return (secretName, secretName);
        }

        private async Task<string> GetDaprSecretValueAsync(string daprSecretName, string daprSecretSection)
        {
            Guard.NotNullOrWhitespace(daprSecretName, nameof(daprSecretName));
            Guard.NotNullOrWhitespace(daprSecretSection, nameof(daprSecretSection));

            using var measurement = DurationMeasurement.Start();
            bool isSuccessful = false;

            try
            {
                using DaprClient client = Options.CreateClient();
                Dictionary<string, string> daprSecrets = await client.GetSecretAsync(SecretStore, daprSecretName);

                if (!daprSecrets.TryGetValue(daprSecretSection, out string secretValue))
                {
                    throw new SecretNotFoundException(daprSecretSection);
                }

                isSuccessful = true;
                return secretValue;
            }
            finally
            {
                if (Options.TrackDependency)
                {
                    Logger.LogDependency("Dapr secret store", daprSecretName, isSuccessful, measurement, new Dictionary<string, object>
                    {
                        ["SecretStore"] = SecretStore,
                        ["SecretSection"] = daprSecretSection
                    }); 
                }
            }
        }
    }
}
