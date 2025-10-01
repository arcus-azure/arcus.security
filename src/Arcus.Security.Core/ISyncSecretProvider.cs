using System;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents an additional synchronous implementation on top of the <see cref="ISecretProvider"/>.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of using the new secret provider interface which has already a synchronous variant of secret retrieval")]
    public interface ISyncSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecret) + " instead")]
        string GetRawSecret(string secretName);

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        Secret GetSecret(string secretName);
    }
}