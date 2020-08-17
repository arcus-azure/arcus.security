using System;
using System.Threading.Tasks;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the environment.
    /// </summary>
    public class EnvironmentVariableSecretProvider : ISecretProvider, ISecretProviderDescription
    {
        internal const EnvironmentVariableTarget DefaultTarget = EnvironmentVariableTarget.Process;

        private readonly EnvironmentVariableTarget _target;
        private readonly string _prefix;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProvider"/> class.
        /// </summary>
        /// <param name="target">The target on which the environment variables should be retrieved.</param>
        /// <param name="prefix">The optional prefix which will be prepended to the secret name when retrieving environment variables.</param>
        public EnvironmentVariableSecretProvider(EnvironmentVariableTarget target = DefaultTarget, string prefix = null)
        {
            _prefix = prefix ?? String.Empty;
            _target = target;
        }

        /// <summary>
        /// Gets the description of the <see cref="ISecretProvider"/> that will be added to the exception message when a secret cannot be found.
        /// For example: 'Azure Key Vault'.
        /// </summary>
        public string Description { get; } = "Environment variables";

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            string secretValue = await GetRawSecretAsync(secretName);
            return new Secret(secretValue);
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            return Task.FromResult(Environment.GetEnvironmentVariable(_prefix + secretName, _target));
        }
    }
}
