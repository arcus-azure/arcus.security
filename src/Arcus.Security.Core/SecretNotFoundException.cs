﻿using System;
using GuardNet;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Exception, thrown when no secret was found, using the given name.
    /// </summary>
    public class SecretNotFoundException : Exception
    {
        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> 
        /// </summary>
        public SecretNotFoundException() : base("The secret was not found.")
        {
        }
        
        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be <c>null</c>.</exception>
        public SecretNotFoundException(string name) : this(name, null)
        {
        }

        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <param name="innerException">Inner exception that can be passed to base exception</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be <c>null</c>.</exception>
        public SecretNotFoundException(string name, Exception innerException) : base($"The secret {name} was not found.", innerException)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            Name = name;
        }

        /// <summary>
        /// Name of the missing key
        /// </summary>
        public string Name { get; } = "undefined";
    }
}
