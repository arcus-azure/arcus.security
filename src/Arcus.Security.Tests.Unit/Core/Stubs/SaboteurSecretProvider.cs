using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    /// <summary>
    /// Represents a <see cref="ISecretProvider"/> that 'sabotage' the secret retrieval by throwing a user-defined exception.
    /// </summary>
    public class SaboteurSecretProvider: ISecretProvider
    {
        private readonly Exception _exception;

        /// <summary>
        /// Initializes a new instance of the <see cref="SaboteurSecretProvider"/> class.
        /// </summary>
        /// <param name="exception">The specific exception to throw during the secret retrieval.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="exception"/> is <c>null</c>.</exception>
        public SaboteurSecretProvider(Exception exception)
        {
            Guard.NotNull(exception, nameof(exception), "Requires an specific exception to sabotage the secret retrieval");
            _exception = exception;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            throw _exception;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecretAsync(string secretName)
        {
            throw _exception;
        }
    }
}
