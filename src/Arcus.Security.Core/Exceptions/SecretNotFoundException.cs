using System;
using GuardNet;

namespace Arcus.Security.Core.Exceptions
{
    /// <summary>
    /// Exception, thrown when no secret was found, using the given name.
    /// </summary>
    [Serializable]
    public class SecretNotFoundException : Exception
    {
        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        public SecretNotFoundException(string name) : this(name, null)
        {
        }

        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <param name="innerException">Inner exception that can be passed to base exception</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        public SecretNotFoundException(string name, Exception innerException) : base($"The secret {name} was not found.", innerException)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            Name = name;
        }

        public string Name { get; }
    }
}
