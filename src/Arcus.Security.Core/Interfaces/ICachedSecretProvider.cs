using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;

namespace Arcus.Security.Core.Interfaces
{
    public interface ICachedSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        Task<string> Get(string secretName, bool ignoreCache);
    }
}
