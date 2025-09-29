using System;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the secret returned from the <see cref="ISecretProvider"/> implementation.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of using secret results")]
    public class Secret
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        /// <param name="value">The secret value.</param>
        /// <param name="version">The version of the secret.</param>
        /// <param name="expirationDate">The expiration date of the secret.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="value"/> cannot be <c>null</c>.</exception>
        public Secret(string value, string version = null, DateTimeOffset? expirationDate = null)
        {
            Value = value ?? throw new ArgumentNullException(nameof(value));
            Version = version;
            Expires = expirationDate;
        }

        /// <summary>
        /// Gets the secret value.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Gets the optional version of the secret.
        /// </summary>
        /// <remarks>Version is not checked for <c>null</c>.</remarks>
        public string Version { get; }

        /// <summary>
        /// Gets the expiration date of the secret.
        /// </summary>
        public DateTimeOffset? Expires { get; }

        /// <summary>
        /// Implicitly converts a <see cref="Secret"/> to a <see cref="string"/> representing the secret <see cref="Value"/>.
        /// </summary>
        public static implicit operator string(Secret secret)
        {
            return secret?.Value;
        }
    }
}
