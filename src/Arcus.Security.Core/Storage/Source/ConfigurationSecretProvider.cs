using System.Threading.Tasks;
using GuardNet;
using Microsoft.Extensions.Configuration;

namespace Arcus.Security.Core.Storage.Source
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the <see cref="IConfiguration"/>. It is recommended to only use this for development purposes.
    /// </summary>
    public class ConfigurationSecretProvider : ISecretProvider
    {
        internal const string DefaultVersion = "1.0.0";

        private readonly IConfiguration _configuration;
        private readonly string _version;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationSecretProvider"/> class.
        /// </summary>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="version">The fixed version to attach to each configured variable.</param>
        public ConfigurationSecretProvider(IConfiguration configuration, string version = DefaultVersion)
        {
            Guard.NotNull(configuration, nameof(configuration));
            Guard.NotNull(version, nameof(version));

            _configuration = configuration;
            _version = version;
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            string secretValue = await GetRawSecretAsync(secretName);
            return new Secret(secretValue, _version);
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            string secretValue = _configuration[secretName];
            return Task.FromResult(secretValue);
        }
    }
}
