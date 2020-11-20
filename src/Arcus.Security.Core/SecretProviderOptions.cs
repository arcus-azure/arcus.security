using System;
using GuardNet;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the additional options to register an <see cref="ISecretProvider"/> implementation to the secret store.
    /// </summary>
    public class SecretProviderOptions
    {
        private string _name;

        /// <summary>
        /// Gets or sets the function to mutate the secret name before looking it up.
        /// </summary>
        public Func<string, string> MutateSecretName { get; set; }

        /// <summary>
        /// Gets or sets the name of the <see cref="ISecretProvider"/> to be registered in the secret store.
        /// </summary>
        public string Name
        {
            get => _name;
            set
            {
                Guard.NotNullOrWhitespace(value, nameof(value), "Requires a non-blank name to register the secret provider");
                _name = value;
            }
        }
    }
}
