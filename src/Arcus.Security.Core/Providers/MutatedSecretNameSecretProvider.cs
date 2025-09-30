using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> that can mutate the secret name provided before looking up the secret.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of moving secret name mutation solely in secret provider registration options")]
    public class MutatedSecretNameSecretProvider : ISyncSecretProvider
    {
        private readonly Func<string, string> _mutateSecretName;
        private readonly ISecretProvider _implementation;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutatedSecretNameSecretProvider"/> class.
        /// </summary>
        /// <param name="implementation">The actual <see cref="ISecretProvider"/> implementation to look up the secret.</param>
        /// <param name="mutateSecretName">The function to mutate the name of the secret before looking up the secret.</param>
        /// <param name="logger">The instance to log diagnostic messages during the secret name mutation.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="implementation"/> or the <paramref name="mutateSecretName"/> is <c>null</c>.
        /// </exception>
        public MutatedSecretNameSecretProvider(ISecretProvider implementation, Func<string, string> mutateSecretName, ILogger logger)
        {
            if (implementation is null)
            {
                throw new ArgumentNullException(nameof(implementation), "Requires a secret provider instance to pass the mutated");
            }

            if (mutateSecretName is null)
            {
                throw new ArgumentNullException(nameof(mutateSecretName), "Requires a transformation function to mutate the incoming secret name to something that the actual secret provider can understand");
            }

            _mutateSecretName = mutateSecretName;
            _implementation = implementation;

            Logger = logger ?? NullLogger<MutatedSecretNameSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the instance to write trace messages during the mutation of the secret names.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            string secretValue = await SafeguardMutateSecretAsync(secretName, mutatedSecretName =>
            {
                return _implementation.GetRawSecretAsync(mutatedSecretName);
            });

            return secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            Secret secret = await SafeguardMutateSecretAsync(secretName, mutatedSecretName =>
            {
                return _implementation.GetSecretAsync(mutatedSecretName);
            });

            return secret;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public string GetRawSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            string secretValue = SafeguardMutateSecret(secretName, mutatedSecretName =>
            {
                return _implementation.GetRawSecret(mutatedSecretName);
            });

            return secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public Secret GetSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            Secret secret = SafeguardMutateSecret(secretName, mutatedSecretName =>
            {
                return _implementation.GetSecret(mutatedSecretName);
            });

            return secret;
        }

        /// <summary>
        /// Safeguards an asynchronous function that will run after the given <paramref name="secretName"/> is mutated.
        /// </summary>
        /// <param name="secretName">The incoming secret name that must be mutated and will be passed along to the given <paramref name="asyncFuncAfterMutation"/>.</param>
        /// <param name="asyncFuncAfterMutation">The function that runs with the mutated secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="asyncFuncAfterMutation"/> is <c>null</c>.</exception>
        protected async Task SafeguardMutateSecretAsync(string secretName, Func<string, Task> asyncFuncAfterMutation)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            if (asyncFuncAfterMutation is null)
            {
                throw new ArgumentNullException(nameof(asyncFuncAfterMutation), "Requires a function to run after the secret name mutation");
            }

            await SafeguardMutateSecretAsync(secretName, async mutatedSecretName =>
            {
                await asyncFuncAfterMutation(mutatedSecretName);

                // Return something unimportant because the method works with task results.
                return 0;
            });
        }

        /// <summary>
        /// Safeguards an asynchronous function that will run after the given <paramref name="secretName"/> is mutated.
        /// </summary>
        /// <typeparam name="T">The return type of the asynchronous function.</typeparam>
        /// <param name="secretName">The incoming secret name that must be mutated and will be passed along to the given <paramref name="asyncFuncAfterMutation"/>.</param>
        /// <param name="asyncFuncAfterMutation">The function that runs with the mutated secret.</param>
        /// <returns>
        ///     The result of the <paramref name="asyncFuncAfterMutation"/> after it's run with the mutated version of the given <paramref name="secretName"/>.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="asyncFuncAfterMutation"/> is <c>null</c>.</exception>
        protected async Task<T> SafeguardMutateSecretAsync<T>(string secretName, Func<string, Task<T>> asyncFuncAfterMutation)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            if (asyncFuncAfterMutation is null)
            {
                throw new ArgumentNullException(nameof(asyncFuncAfterMutation), "Requires a function to run after the secret name mutation");
            }

            string mutatedSecretName = MutateSecretName(secretName);
            Task<T> task = asyncFuncAfterMutation(mutatedSecretName);

            if (task is null)
            {
                throw new InvalidOperationException(
                    $"Asynchronous failure during calling the secret provider with the mutated secret '{mutatedSecretName}'");
            }

            try
            {
                return await task;
            }
            catch (Exception exception)
            {
                Logger.LogWarning(
                    exception, "Failure during using secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw;
            }
        }

        /// <summary>
        /// Safeguards an asynchronous function that will run after the given <paramref name="secretName"/> is mutated.
        /// </summary>
        /// <typeparam name="T">The return type of the asynchronous function.</typeparam>
        /// <param name="secretName">The incoming secret name that must be mutated and will be passed along to the given <paramref name="afterMutation"/>.</param>
        /// <param name="afterMutation">The function that runs with the mutated secret.</param>
        /// <returns>
        ///     The result of the <paramref name="afterMutation"/> after it's run with the mutated version of the given <paramref name="secretName"/>.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="afterMutation"/> is <c>null</c>.</exception>
        protected T SafeguardMutateSecret<T>(string secretName, Func<string, T> afterMutation)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            if (afterMutation is null)
            {
                throw new ArgumentNullException(nameof(afterMutation), "Requires a function to run after the secret name mutation");
            }

            string mutatedSecretName = MutateSecretName(secretName);

            try
            {
                return afterMutation(mutatedSecretName);
            }
            catch (Exception exception)
            {
                Logger.LogWarning(exception, "Failure during using secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw;
            }
        }

        private string MutateSecretName(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            try
            {
                Logger.LogTrace("Start mutating secret name '{SecretName}'...", secretName);
                string mutateSecretName = _mutateSecretName(secretName);
                Logger.LogTrace("Secret name '{OriginalSecretName}' mutated to '{MutatedSecretName}'", secretName, mutateSecretName);

                return mutateSecretName;
            }
            catch (Exception exception)
            {
                Logger.LogWarning(exception, "Failure during secret name mutation of '{SecretName}'", secretName);
                throw new NotSupportedException(
                    $"The secret '{secretName}' was not correct input for the secret name mutation expression", exception);
            }
        }
    }
}
