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
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string Name 
        {  
            get => _name;
            set
            {
                Guard.For<ArgumentException>(
                    () => value != null && String.IsNullOrWhiteSpace(value),
                    "Requires a non-blank value for the name of the secret provider to be registered in the secret store");
                
                _name = value;
            }
        }
    }
}
