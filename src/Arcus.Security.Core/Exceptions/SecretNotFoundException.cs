using System;
using System.Collections.Generic;
using System.Text;

namespace Arcus.Security.Core.Exceptions
{
    /// <summary>
    /// Exception, thrown when no secret was found, using the given name.
    /// </summary>
    public class SecretNotFoundException : Exception
    {
        public string Name { get;  }
        public SecretNotFoundException(string name) : base($"The secret {name} was not found.")
        {
            Name = name;
        }
    }
}
