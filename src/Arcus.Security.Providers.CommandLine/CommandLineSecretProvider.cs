using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.CommandLine;

namespace Arcus.Security.Providers.CommandLine
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> implementation that provides the command line arguments as secrets to the secret store.
    /// </summary>
    public class CommandLineSecretProvider : ISecretProvider
    {
        private readonly CommandLineConfigurationProvider _configurationProvider;
        
        /// <summary>
        /// Initializes a new instance of the <see cref="CommandLineSecretProvider"/> class.
        /// </summary>
        /// <param name="configurationProvider">The command line <see cref="IConfigurationProvider"/> to load the command arguments as secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configurationProvider"/> is <c>null</c>.</exception>
        public CommandLineSecretProvider(CommandLineConfigurationProvider configurationProvider)
        {
            Guard.NotNull(configurationProvider, nameof(configurationProvider), "Requires a command line configuration provider instance to load the command arguments as secrets");
            _configurationProvider = configurationProvider;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the command line argument secret");
            
            string secretValue = await GetRawSecretAsync(secretName);
            if (secretValue is null)
            {
                return null;
            }

            return new Secret(secretValue);

        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the command line argument secret");
            
            if (_configurationProvider.TryGet(secretName, out string secretValue))
            {
                return Task.FromResult(secretValue);
            }
            
            return Task.FromResult<string>(null);
        }
    }
}
