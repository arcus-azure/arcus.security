using System;
using System.Threading.Tasks;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the environment.
    /// </summary>
    public class EnvironmentVariableSecretProvider : ISyncSecretProvider
    {
        internal const EnvironmentVariableTarget DefaultTarget = EnvironmentVariableTarget.Process;

        private readonly EnvironmentVariableTarget _target;
        private readonly string _prefix;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProvider"/> class.
        /// </summary>
        /// <param name="target">The target on which the environment variables should be retrieved.</param>
        /// <param name="prefix">The optional prefix which will be prepended to the secret name when retrieving environment variables.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="target"/> is outside the bounds of the enumeration.</exception>
        public EnvironmentVariableSecretProvider(EnvironmentVariableTarget target = DefaultTarget, string prefix = null)
        {
            if (!Enum.IsDefined(typeof(EnvironmentVariableTarget), target))
            {
                throw new ArgumentException($"Requires an environment variable target of either '{EnvironmentVariableTarget.Process}', '{EnvironmentVariableTarget.Machine}', or '{EnvironmentVariableTarget.User}'", nameof(target));
            }

            _prefix = prefix ?? String.Empty;
            _target = target;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the environment secret", nameof(secretName));
            }

            Secret secret = GetSecret(secretName);
            return Task.FromResult(secret);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public Task<string> GetRawSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the environment secret", nameof(secretName));
            }

            string secretValue = GetRawSecret(secretName);
            return Task.FromResult(secretValue);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public Secret GetSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the environment secret", nameof(secretName));
            }

            string secretValue = Environment.GetEnvironmentVariable(_prefix + secretName, _target);
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
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecret) + " instead")]
        public string GetRawSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the environment secret", nameof(secretName));
            }

            string environmentVariable = Environment.GetEnvironmentVariable(_prefix + secretName, _target);
            return environmentVariable;
        }
    }
}
