using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using GuardNet;

[assembly: InternalsVisibleTo("Arcus.Security.Providers.HashiCorp")]
[assembly: InternalsVisibleTo("Arcus.Security.Providers.DockerSecrets")]
[assembly: InternalsVisibleTo("Arcus.Security.Providers.CommandLine")]

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> allows developers to build specific Secret key providers.
    /// </summary>
    public interface ISecretProvider
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        Task<string> GetRawSecretAsync(string secretName);

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        Task<Secret> GetSecretAsync(string secretName);
    }
}

namespace Arcus.Security
{
    /// <summary>
    /// Represents a provider that can retrieve secrets based on a given name.
    /// </summary>
    internal interface ISecretProvider
    {
        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        Task<SecretResult> GetSecretAsync(string secretName)
        {
            return Task.FromResult(GetSecret(secretName));
        }

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult GetSecret(string secretName);
    }

    /// <summary>
    /// Represents the possible failures in the <see cref="SecretResult"/> occured during the retrieval of secrets
    /// using the <see cref="ISecretProvider.GetSecret"/> or <see cref="ISecretProvider.GetSecretAsync"/> operations.
    /// </summary>
    public enum SecretFailure
    {
        /// <summary>
        /// Gets the secret failure when a secret cannot be found by the <see cref="ISecretProvider"/>.
        /// This is an expected failure when working with a secret store with multiple providers that complement each other.
        /// </summary>
        NotFound = 0,

        /// <summary>
        /// Gets the secret failure when the retrieval of the secret was interrupted by the <see cref="ISecretProvider"/>.
        /// This is an unexpected failure that could indicate a problem with the provider's implementation.
        /// </summary>
        Interrupted
    }

    /// <summary>
    /// Represents the result of a secret retrieval operation, which can either be successful or contain failure information.
    /// </summary>
    public class SecretResult
    {
        private readonly string _secretName, _secretValue, _secretVersion, _failureMessage;
        private readonly SecretFailure _failure;
        private readonly DateTimeOffset? _expirationDate;
        private readonly Exception _failureCause;

        private SecretResult(SecretFailure failure, string failureMessage, Exception failureCause)
        {
            Guard.NotNullOrWhitespace(failureMessage, nameof(failureMessage));

            _failure = failure;
            _failureMessage = failureMessage;
            _failureCause = failureCause;

            IsSuccess = false;
        }

        private SecretResult(string secretName, string secretValue, string secretVersion, DateTimeOffset expirationDate)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretValue));
            Guard.NotNullOrWhitespace(secretValue, nameof(secretValue));

            _secretName = secretName;
            _secretValue = secretValue;
            _secretVersion = secretVersion;
            _expirationDate = expirationDate;

            IsSuccess = true;
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> or <paramref name="secretValue"/> is blank.</exception>
        public static SecretResult Success(string secretName, string secretValue)
        {
            return new SecretResult(secretName, secretValue, secretVersion: null, DateTimeOffset.MaxValue);
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="secretName"/>, <paramref name="secretValue"/> or <paramref name="secretVersion"/> is blank.
        /// </exception>
        public static SecretResult Success(string secretName, string secretValue, string secretVersion, DateTimeOffset expirationDate)
        {
            return new SecretResult(secretName, secretValue, secretVersion, expirationDate);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret that was not available on an <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an expected failure when working with a secret store with multiple providers that complement each other.
        /// </remarks>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="failureMessage"/> is blank.</exception>
        public static SecretResult NotFound(string failureMessage)
        {
            return new SecretResult(SecretFailure.NotFound, failureMessage, null);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret that was not available on an <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an expected failure when working with a secret store with multiple providers that complement each other.
        /// </remarks>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <param name="failureCause">The exception that was the cause of the current failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="failureMessage"/> is blank.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="failureCause"/> is <c>null</c>.</exception>
        public static SecretResult NotFound(string failureMessage, Exception failureCause)
        {
            return new SecretResult(SecretFailure.NotFound, failureMessage, failureCause);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret retrieval operation that was interrupted unexpectedly
        /// in the <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an unexpected failure that could indicate a problem with the provider's implementation.
        /// </remarks>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <param name="failureCause">The exception that was the cause of the current failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="failureMessage"/> is blank.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="failureCause"/> is <c>null</c>.</exception>
        public static SecretResult Interrupted(string failureMessage, Exception failureCause)
        {
            return new SecretResult(SecretFailure.Interrupted, failureMessage, failureCause);
        }

        /// <summary>
        /// Gets the boolean flag indicating whether the secret retrieval was successful or not.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the secret value that was retrieved from the secret provider.
        /// </summary>
        public string Name => IsSuccess ? _secretName : throw new InvalidOperationException($"[Arcus] cannot get secret name as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the value of the secret that was retrieved from the secret provider.
        /// </summary>
        public string Value => IsSuccess ? _secretValue : throw new InvalidOperationException($"[Arcus] cannot get secret value as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the version of the secret that was retrieved from the secret provider.
        /// </summary>
        public string Version => IsSuccess ? _secretVersion : throw new InvalidOperationException($"[Arcus] cannot get secret version as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the expiration date of the secret that was retrieved from the secret provider.
        /// </summary>
        public DateTimeOffset? Expiration => IsSuccess ? _expirationDate : throw new InvalidOperationException($"[Arcus] cannot get secret expiration date as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the type of failure that occured during the secret retrieval.
        /// </summary>
        public SecretFailure Failure => !IsSuccess ? _failure : throw new InvalidOperationException($"[Arcus] cannot get secret failure as the secret retrieval was successful: {_secretName}");

        /// <summary>
        /// Gets the failure message that was returned when the secret retrieval failed.
        /// </summary>
        public string FailureMessage => !IsSuccess ? _failureMessage : throw new InvalidOperationException($"[Arcus] cannot get failure message as the secret retrieval was successful: {_secretName}");

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public Exception FailureCause => !IsSuccess ? _failureCause : throw new InvalidOperationException($"[Arcus] cannot get failure cause as the secret retrieval was successful: {_secretName}");

        /// <summary>
        /// Converts the <see cref="SecretResult"/> to a string representation, which is the secret value.
        /// </summary>
        public static implicit operator string(SecretResult result)
        {
            return result?.Value;
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        public override string ToString()
        {
            return IsSuccess ? $"[Success]: {Name}" : $"[Failure]: {FailureMessage} {FailureCause}";
        }
    }
}
