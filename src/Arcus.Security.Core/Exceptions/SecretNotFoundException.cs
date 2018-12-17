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
        public SecretNotFoundException(string name) : this(name, null)
        {
        }

        public SecretNotFoundException(string name, Exception innerException) : base($"The secret {name} was not found.", innerException)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            Name = name;
        }

        public string Name { get; }
    }
}
