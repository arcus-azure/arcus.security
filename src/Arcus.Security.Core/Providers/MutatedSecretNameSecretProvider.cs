using System;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> that can mutate the secret name provided before looking up the secret.
    /// </summary>
    public class MutatedSecretNameSecretProvider : ISecretProvider
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
            Guard.NotNull(implementation, nameof(implementation), "Requires an secret provider instance to pass the mutated secret name to");
            Guard.NotNull(mutateSecretName, nameof(mutateSecretName), 
                "Requires an transformation function to mutate the incoming secret name to something that the actual secret provider can understand");

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
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string secretValue = await SafeguardMutateSecretNameAsync(secretName, mutated => _implementation.GetRawSecretAsync(mutated));
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            Secret secret = await SafeguardMutateSecretNameAsync(secretName, mutated => _implementation.GetSecretAsync(mutated));
            return secret;
        }

        /// <summary>
        /// Safeguards the previously specified mutated secret name function with built-in exception handling.
        /// Handles the result of the <see cref="MutateSecretName"/> into the inner specified <see cref="ISecretProvider"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret to be mutated.</param>
        /// <param name="asyncFuncAfterMutation">The function to execute after the mutation.</param>
        protected async Task SafeguardMutateSecretNameAsync(string secretName, Func<string, Task> asyncFuncAfterMutation)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");
            Guard.NotNull(asyncFuncAfterMutation, nameof(asyncFuncAfterMutation), "Requires a asynchronous function to execute after the secret name mutation");

            await SafeguardMutateSecretNameAsync(secretName, async mutated =>
            {
                await asyncFuncAfterMutation(mutated);
                
                // Return something so we can use other overload.
                return 0;
            });
        }

        /// <summary>
        /// Safeguards the previously specified mutated secret name function with built-in exception handling.
        /// Handles the result of the <see cref="MutateSecretName"/> into the inner specified <see cref="ISecretProvider"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret to be mutated.</param>
        /// <param name="asyncFuncAfterMutation">The function to execute after the mutation.</param>
        /// <returns>
        ///     The value that was returned from the <paramref name="asyncFuncAfterMutation"/> given the mutated version of the given <paramref name="secretName"/>.
        /// </returns>
        protected async Task<T> SafeguardMutateSecretNameAsync<T>(string secretName, Func<string, Task<T>> asyncFuncAfterMutation)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");
            Guard.NotNull(asyncFuncAfterMutation, nameof(asyncFuncAfterMutation), "Requires a asynchronous function to execute after the secret name mutation");

            string mutatedSecretName = MutateSecretName(secretName);
            Task<T> secretAsync = asyncFuncAfterMutation(mutatedSecretName);

            if (secretAsync is null)
            {
                throw new SecretNotFoundException(mutatedSecretName);
            }

            try
            {
                return await secretAsync;
            }
            catch (Exception exception)
            {
                Logger.LogError(
                    exception, "Failure during using secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
        }

        /// <summary>
        /// Transforms the given <paramref name="secretName"/> to a new structure in which way the <see cref="ISecretProvider"/> can retrieve the actual secret value.
        /// </summary>
        /// <param name="secretName">The incoming secret name.</param>
        /// <returns>
        ///     The mutated secret name that will be send to the actual <see cref="ISecretProvider"/> instance.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        protected string MutateSecretName(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            try
            {
                Logger.LogTrace("Start mutating secret name '{SecretName}'...", secretName);
                string mutateSecretName = _mutateSecretName(secretName);
                Logger.LogInformation("Secret name '{OriginalSecretName}' mutated to '{MutatedSecretName}'", secretName, mutateSecretName);

                return mutateSecretName;
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "Failure during secret name mutation of '{SecretName}'", secretName);
                throw new NotSupportedException(
                    $"The secret '{secretName}' was not correct input for the secret name mutation expression", exception);
            }
        }
    }
}
