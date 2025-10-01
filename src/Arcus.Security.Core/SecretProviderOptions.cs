using System;
using System.Collections.Generic;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the additional options to register an <see cref="ISecretProvider"/> implementation to the secret store.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of a new " + nameof(SecretProviderRegistrationOptions) + " model")]
    public class SecretProviderOptions
    {
        private readonly IDictionary<string, int> _versionedSecretNames = new Dictionary<string, int>();

        private string _name;

        /// <summary>
        /// Gets or sets the function to mutate the secret name before looking it up.
        /// </summary>
        public Func<string, string> MutateSecretName { get; set; }

        /// <summary>
        /// Gets or sets the name of the <see cref="ISecretProvider"/> to be registered in the secret store.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string Name
        {
            get => _name;
            set
            {
                if (value != null && string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("Requires a non-blank value for the name of the secret provider to be registered in the secret store", nameof(value));
                }

                _name = value;
            }
        }

        /// <summary>
        /// Makes the given <paramref name="secretName"/> a versioned secret
        /// so that a set of <paramref name="allowedVersions"/> of that secret can be retrieved.
        /// </summary>
        /// <param name="secretName">The name of the secret that is allowed to have multiple versions.</param>
        /// <param name="allowedVersions">The amount of versions a the secret is allowed to have.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="allowedVersions"/> is less than zero.</exception>
        public void AddVersionedSecret(string secretName, int allowedVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to make the secret a versioned secret in the secret store", nameof(secretName));
            }

            if (allowedVersions < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(allowedVersions), allowedVersions, "Requires at least 1 secret version to make the secret a versioned secret in the secret store");
            }

            _versionedSecretNames[secretName] = allowedVersions;
        }

        /// <summary>
        /// Determines whether the given <paramref name="secretName"/> is registered as a versioned secret in this secret provider registration.
        /// </summary>
        /// <param name="secretName">The name of the secret that is inspected to be a versioned secret in this secret provider registration.</param>
        /// <param name="allowedVersions">The allowed versions the <paramref name="secretName"/> has in this secret provider registration.</param>
        /// <returns>
        ///     [true] if the secret provider registration has registered the given <paramref name="secretName"/> as a versioned secret; [false] otherwise.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        internal bool TryGetAllowedSecretVersions(string secretName, out int allowedVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to make the secret a versioned secret in the secret store", nameof(secretName));
            }

            return _versionedSecretNames.TryGetValue(secretName, out allowedVersions);
        }
    }
}
