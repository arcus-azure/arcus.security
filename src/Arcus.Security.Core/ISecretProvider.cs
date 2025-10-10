using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> allows developers to build specific Secret key providers.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor a new interface 'Arcus.Security.ISecretProvider'")]
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
    public interface ISecretProvider
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
    /// Extensions on the <see cref="ISecretProvider"/> to ease the migration to the new secret retrieval operations.
    /// </summary>
    public static class DeprecatedSecretProviderExtensions
    {
        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0, please use the new " + nameof(ISecretProvider.GetSecretAsync) + " overloads with secret results")]
        public static async Task<Secret> GetSecretAsync(this ISecretProvider provider, string secretName)
        {
            return await provider.GetSecretAsync(secretName);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0, please use the new " + nameof(ISecretProvider.GetSecret) + " overloads with secret results")]
        public static Secret GetSecret(this ISecretProvider provider, string secretName)
        {
            return provider.GetSecret(secretName);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0, please use the new " + nameof(ISecretProvider.GetSecretAsync) + " overloads with secret results")]
        public static async Task<string> GetRawSecretAsync(this ISecretProvider provider, string secretName)
        {
            Secret secret = await GetSecretAsync(provider, secretName);
            return secret.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0, please use the new " + nameof(ISecretProvider.GetSecret) + " overloads with secret results")]
        public static string GetRawSecret(this ISecretProvider provider, string secretName)
        {
            Secret secret = GetSecret(provider, secretName);
            return secret.Value;
        }
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
    [DebuggerDisplay("{IsSuccess ? \"[Success]\" + {Name} : \"[Failure] \" + {Name} + \" \" + {FailureMessage} + \" \" + {FailureCause}")]
    public class SecretResult
    {
        private readonly string _value, _version, _failureMessage;
        private readonly SecretFailure _failure;
        private readonly DateTimeOffset? _expirationDate;
        private readonly Exception _failureCause;

        private SecretResult(string name, SecretFailure failure, string failureMessage, Exception failureCause)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentException.ThrowIfNullOrWhiteSpace(failureMessage);

            _failure = failure;
            _failureMessage = failureMessage;
            _failureCause = failureCause;

            Name = name;
            IsSuccess = false;
        }

        private SecretResult(string name, string value, string version, DateTimeOffset expirationDate)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentException.ThrowIfNullOrWhiteSpace(value);

            _value = value;
            _version = version;
            _expirationDate = expirationDate;

            Name = name;
            IsSuccess = true;
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the secret <paramref name="name"/> or <paramref name="value"/> is blank.</exception>
        public static SecretResult Success(string name, string value)
        {
            return Success(name, value, version: null, DateTimeOffset.MaxValue);
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when the secret <paramref name="name"/>, <paramref name="value"/> or <paramref name="version"/> is blank.
        /// </exception>
        public static SecretResult Success(string name, string value, string version, DateTimeOffset expirationDate)
        {
            return new SecretResult(name, value, version, expirationDate);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret that was not available on an <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an expected failure when working with a secret store with multiple providers that complement each other.
        /// </remarks>
        /// <param name="name">The name of the secret that failed to be retrieved.</param>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> or the <paramref name="failureMessage"/> is blank.</exception>
        public static SecretResult NotFound(string name, string failureMessage)
        {
            return NotFound(name, failureMessage, failureCause: null);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret that was not available on an <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an expected failure when working with a secret store with multiple providers that complement each other.
        /// </remarks>
        /// <param name="name">The name of the secret that failed to be retrieved.</param>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <param name="failureCause">The exception that was the cause of the current failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> or the <paramref name="failureMessage"/> is blank.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="failureCause"/> is <c>null</c>.</exception>
        public static SecretResult NotFound(string name, string failureMessage, Exception failureCause)
        {
            return new SecretResult(name, SecretFailure.NotFound, failureMessage, failureCause);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance that represents a secret retrieval operation that was interrupted unexpectedly
        /// in the <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     This is an unexpected failure that could indicate a problem with the provider's implementation.
        /// </remarks>
        /// <param name="name">The name of the secret that failed to be retrieved.</param>
        /// <param name="failureMessage">The user message that describes the failure.</param>
        /// <param name="failureCause">The exception that was the cause of the current failure.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> or the <paramref name="failureMessage"/> is blank.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="failureCause"/> is <c>null</c>.</exception>
        public static SecretResult Interrupted(string name, string failureMessage, Exception failureCause)
        {
            return new SecretResult(name, SecretFailure.Interrupted, failureMessage, failureCause);
        }

        /// <summary>
        /// Gets the boolean flag indicating whether the secret retrieval was successful or not.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the secret value that was retrieved from the secret provider.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the value of the secret that was retrieved from the secret provider.
        /// </summary>
        /// <remarks>
        ///   Is available when <see cref="IsSuccess"/> is <c>true</c>; also as an implicit conversion to <see cref="string"/>:
        ///   <example>
        ///     <code>
        ///     // Retrieve the secret result from the provider and interact with result yourself.
        ///     SecretResult result = await secretProvider.GetSecretAsync("MySecret");
        ///     string secretValue = result.Value;
        ///     
        ///     // Retrieve the secret result from the provider and implicitly convert it to a string.
        ///     string secretValue = await secretProvider.GetSecretAsync("MySecret");
        ///     </code>
        ///   </example>
        /// </remarks>
        public string Value => IsSuccess ? _value : throw new InvalidOperationException($"[Arcus] cannot get secret value as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the version of the secret that was retrieved from the secret provider.
        /// </summary>
        /// <remarks>
        ///     Only available when <see cref="IsSuccess"/> is <c>true</c> and the secret provider supports versioning.
        /// </remarks>
        public string Version => IsSuccess ? _version : throw new InvalidOperationException($"[Arcus] cannot get secret version as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the expiration date of the secret that was retrieved from the secret provider.
        /// </summary>
        /// <remarks>
        ///     Only available when <see cref="IsSuccess"/> is <c>true</c> and the secret provider supports expiration dates.
        /// </remarks>
        public DateTimeOffset? Expiration => IsSuccess ? _expirationDate : throw new InvalidOperationException($"[Arcus] cannot get secret expiration date as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the type of failure that occured during the secret retrieval.
        /// </summary>
        /// <remarks>
        ///     Only available when <see cref="IsSuccess"/> is <c>false</c>.
        /// </remarks>
        public SecretFailure Failure => !IsSuccess ? _failure : throw new InvalidOperationException($"[Arcus] cannot get secret failure as the secret retrieval was successful: {Name}");

        /// <summary>
        /// Gets the failure message that was returned when the secret retrieval failed.
        /// </summary>
        /// <remarks>
        ///     Only available when <see cref="IsSuccess"/> is <c>false</c>.
        /// </remarks>
        public string FailureMessage => !IsSuccess ? _failureMessage : throw new InvalidOperationException($"[Arcus] cannot get failure message as the secret retrieval was successful: {Name}");

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        /// <remarks>
        ///     Only available when <see cref="IsSuccess"/> is <c>false</c>.
        /// </remarks>
        public Exception FailureCause => !IsSuccess ? _failureCause : throw new InvalidOperationException($"[Arcus] cannot get failure cause as the secret retrieval was successful: {Name}");

        /// <summary>
        /// Converts the <see cref="SecretResult"/> to a string representation, which is the secret value.
        /// </summary>
        public static implicit operator string(SecretResult result)
        {
            return result?.Value;
        }

        /// <summary>
        /// Converts the <see cref="SecretResult"/> to its deprecated previous implementation.
        /// </summary>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
#pragma warning disable CS0618
        public static implicit operator Secret(SecretResult result)
#pragma warning restore
        {
            if (result.IsSuccess)
            {
                return new Secret(result.Value, result.Version, result._expirationDate);
            }

            return result.Failure switch
            {
                SecretFailure.Interrupted => throw result.FailureCause,
                _ => throw new SecretNotFoundException(result.ToString()),
            };
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        public override string ToString()
        {
            if (IsSuccess)
            {
                var versionPart = !string.IsNullOrWhiteSpace(_version) ? $" (v{_version})" : string.Empty;
                var expirationPart = _expirationDate.HasValue ? $", expires {_expirationDate:s}" : string.Empty;
                return $"[Success] {Name}{versionPart}{expirationPart}";
            }

            var causePart = _failureCause != null
                ? $" | cause: {_failureCause.GetType().Name}: {_failureCause.Message}"
                : string.Empty;

            return $"[Failure:{_failure}] {Name}: {_failureMessage}{causePart}";
        }
    }

    /// <summary>
    /// Represents the aggregated result of a secrets retrieval operation, which can either be successful or contain failure information.
    /// </summary>
    /// <remarks>
    ///     Useful for when <see cref="ISecretProvider"/>s have to return multiple secrets at once, for example when working with versioned secrets.
    /// </remarks>
    public class SecretsResult : IEnumerable<SecretResult>
    {
        private readonly IReadOnlyCollection<SecretResult> _secrets;
        private readonly string _failureMessage;
        private readonly Exception _failureCause;

        private SecretsResult(SecretResult[] secrets)
        {
            _secrets = secrets;
            IsSuccess = secrets.All(secret => secret.IsSuccess);

            (string FailureMessage, Exception FailureCause)[] failures =
                secrets.Where(s => !s.IsSuccess).Select(s => (s.FailureMessage, s.FailureCause)).ToArray();

            _failureMessage = string.Join(Environment.NewLine, failures.Select(f => f.FailureMessage));
            _failureCause = failures.Length > 0 ? new AggregateException(failures.Select(f => f.FailureCause)) : null;
        }

        /// <summary>
        /// Creates a <see cref="SecretsResult"/> instance with the given collection of secrets.
        /// </summary>
        /// <param name="secrets">The sequence of secrets that were retrieved.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secrets"/> is <c>null</c>.</exception>
        public static SecretsResult Create(IEnumerable<SecretResult> secrets)
        {
            ArgumentNullException.ThrowIfNull(secrets);
            return new SecretsResult(secrets.ToArray());
        }

        /// <summary>
        /// Gets the boolean flag indicating whether the secrets retrieval was successful or not.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public string FailureMessage => !IsSuccess ? _failureMessage : throw new InvalidOperationException("Cannot get failure message as the secrets retrieval was successful");

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public Exception FailureCause => !IsSuccess ? _failureCause : throw new InvalidOperationException("Cannot get failure cause as the secrets retrieval was successful");

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An enumerator that can be used to iterate through the collection.</returns>
        public IEnumerator<SecretResult> GetEnumerator()
        {
            return _secrets.GetEnumerator();
        }

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>An <see cref="IEnumerator" /> object that can be used to iterate through the collection.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
