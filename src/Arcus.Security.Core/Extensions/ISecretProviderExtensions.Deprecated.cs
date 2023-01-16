using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using GuardNet;

namespace Arcus.Security.Core.Extensions
{
    /// <summary>
    /// Extensions on the <see cref="ISecretProvider"/> to retrieve several secret values based on configured allowed versions.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    [ExcludeFromCodeCoverage]
    public static class ISecretProviderExtensions
    {
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
        [Obsolete("Use the " + nameof(Core.ISecretProviderExtensions.GetRawSecretsAsync) + " extension instead")]
        public static async Task<IEnumerable<string>> GetRawSecretsAsync(this ISecretProvider secretProvider, string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

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
        [Obsolete("Use the " + nameof(Core.ISecretProviderExtensions.GetSecretsAsync) + " extension instead")]
        public static async Task<IEnumerable<Secret>> GetSecretsAsync(this ISecretProvider secretProvider, string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

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