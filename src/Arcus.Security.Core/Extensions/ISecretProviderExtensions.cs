using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// ReSharper disable once CheckNamespace
namespace Arcus.Security.Core
{
    /// <summary>
    /// Extensions on the <see cref="ISecretProvider"/> to retrieve several secret values based on configured allowed versions.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class ISecretProviderExtensions
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretProvider">The injected secret provider instance.</param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public static string GetRawSecret(this ISecretProvider secretProvider, string secretName)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider), "Requires a secret provider to synchronously look up the secret");
            }

            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (secretProvider is ISyncSecretProvider composite)
            {
                string secretValue = composite.GetRawSecret(secretName);
                return secretValue;
            }

            throw new NotSupportedException(
                $"Cannot retrieve secret '{secretName}' because the '{nameof(GetRawSecret)}' method is called on the '{secretProvider.GetType().Name}' implementation that does not implement the '{nameof(ISyncSecretProvider)}'");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretProvider">The injected secret provider instance.</param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public static Secret GetSecret(this ISecretProvider secretProvider, string secretName)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider
            }

            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (secretProvider is ISyncSecretProvider composite)
            {
                Secret secret = composite.GetSecret(secretName);
                return secret;
            }

            throw new NotSupportedException(
                $"Cannot retrieve secret '{secretName}' because the '{nameof(GetRawSecret)}' method is called on a '{secretProvider.GetType().Name}' that does not implement the '{nameof(ISyncSecretProvider)}'");
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the given <paramref name="secretName"/>.
        /// </summary>
        /// <remarks>
        ///     This extension is made for easy access to the versions of a secret, and is expected to be used on the <paramref name="secretProvider"/> secret store implementation,
        ///     any other uses will fallback on the general secret retrieval. In that case, the resulting sequence will contain a single secret value.
        /// </remarks>
        /// <param name="secretProvider">The secret store composite secret provider.</param>
        /// <param name="secretName">The name of the secret that was made versioned with <see cref="SecretProviderOptions.AddVersionedSecret"/>.</param>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public static async Task<IEnumerable<string>> GetRawSecretsAsync(this ISecretProvider secretProvider, string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (secretProvider is CompositeSecretProvider composite)
            {
                IEnumerable<string> secretValues = await composite.GetRawSecretsAsync(secretName);
                return secretValues.ToArray();
            }

            string secretValue = await secretProvider.GetRawSecretAsync(secretName);
            return new[] { secretValue };
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the given <paramref name="secretName"/>.
        /// </summary>
        /// <remarks>
        ///     This extension is made for easy access to the versions of a secret, and is expected to be used on the <paramref name="secretProvider"/> secret store implementation,
        ///     any other uses will fallback on the general secret retrieval. In that case, the resulting sequence will contain a single secret value.
        /// </remarks>
        /// <param name="secretProvider">The secret store composite secret provider.</param>
        /// <param name="secretName">The name of the secret that was made versioned with <see cref="SecretProviderOptions.AddVersionedSecret"/>.</param>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public static async Task<IEnumerable<Secret>> GetSecretsAsync(this ISecretProvider secretProvider, string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (secretProvider is CompositeSecretProvider composite)
            {
                IEnumerable<Secret> secrets = await composite.GetSecretsAsync(secretName);
                return secrets.ToArray();
            }

            Secret secret = await secretProvider.GetSecretAsync(secretName);
            return new[] { secret };
        }
    }
}