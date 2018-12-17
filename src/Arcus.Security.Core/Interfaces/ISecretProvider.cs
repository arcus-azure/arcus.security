using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;

namespace Arcus.Security.Core.Interfaces
{
    /// <summary>
    /// <see cref="ISecretProvider"/> allows developers to build specific Secret key providers.
    /// </summary>
    public interface ISecretProvider
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="name">The name of the secret key</param>
        /// <returns>Returns a <see cref="Task{string}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        Task<string> GetAsync(string name);
    }
}
