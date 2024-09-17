using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration;
using GuardNet;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Provider to retrieve configuration tokens via an <see cref="ISecretProvider"/> implementation.
    /// </summary>
    internal class ArcusConfigurationProvider : ConfigurationProvider
    {
        private readonly ISecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArcusConfigurationProvider"/> class.
        /// </summary>
        /// <param name="secretProvider">The provider to retrieve secret values for configuration tokens.</param>
        internal ArcusConfigurationProvider(ISecretProvider secretProvider)
        {
            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        }
        
        /// <summary>
        /// Attempts to find a value with the given key, returns true if one is found, false otherwise.
        /// </summary>
        /// <param name="key">The key to lookup.</param>
        /// <param name="value">The value found at key if one is found.</param>
        /// <returns>True if key has a value, false otherwise.</returns>
        public override bool TryGet(string key, out string value)
        {
            Task<string> getSecretValueAsync = _secretProvider.GetRawSecretAsync(key);
            if (getSecretValueAsync != null) 
            {
                string secretValue = getSecretValueAsync.ConfigureAwait(false).GetAwaiter().GetResult();
                
                value = secretValue;
                return secretValue != null;
            }

            value = null;
            return false;
        }
    }
}
