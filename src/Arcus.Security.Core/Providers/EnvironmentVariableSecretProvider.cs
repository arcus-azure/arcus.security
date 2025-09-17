using System;
using System.Threading.Tasks;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the environment.
    /// </summary>
    public class EnvironmentVariableSecretProvider :
#pragma warning disable CS0612 // Type or member is obsolete
        ISyncSecretProvider,
#pragma warning restore CS0612 // Type or member is obsolete
        Security.ISecretProvider
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

            _prefix = prefix ?? string.Empty;
            _target = target;
        }

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult Security.ISecretProvider.GetSecret(string secretName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            string secretValue = Environment.GetEnvironmentVariable(_prefix + secretName, _target);
            return secretValue is null
                ? SecretResult.NotFound($"cannot find secret '{_prefix}{secretName} in environment variables with target '{_target}'")
                : SecretResult.Success(secretName, secretValue);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name.
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public Task<Secret> GetSecretAsync(string secretName)
        {
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
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public Secret GetSecret(string secretName)
        {
            SecretResult result = ((Security.ISecretProvider) this).GetSecret(secretName);
            return result.IsSuccess ? new Secret(result.Value) : null;
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
            return GetSecret(secretName)?.Value;
        }
    }
}
