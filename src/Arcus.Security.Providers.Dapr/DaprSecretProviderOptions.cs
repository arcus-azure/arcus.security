using System;
using System.Collections.Generic;
using Dapr.Client;
using GuardNet;

namespace Arcus.Security.Providers.Dapr
{
    /// <summary>
    /// Represents the available options for the <see cref="DaprSecretProvider"/>.
    /// </summary>
    public class DaprSecretProviderOptions
    {
        private string _grpcEndpoint, _httpEndpoint, _daprApiToken;

        /// <summary>
        /// Gets the optional metadata to be sent together with the Dapr runtime upon each secret retrieval.
        /// </summary>
        internal IDictionary<string, string> Metadata { get; } = new Dictionary<string, string>();

        /// <summary>
        /// Overrides the gRPC endpoint used by <see cref="DaprClient" /> for communicating with the Dapr runtime.
        /// </summary>
        /// <remarks>
        ///     The URI endpoint to use for gRPC calls to the Dapr runtime. The default value will be
        ///     <c>http://127.0.0.1:DAPR_GRPC_PORT</c> where <c>DAPR_GRPC_PORT</c> represents the value of the
        ///     <c>DAPR_GRPC_PORT</c> environment variable.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string GrpcEndpoint
        {
            get => _grpcEndpoint;
            set
            {
                Guard.NotNullOrWhitespace(value, nameof(value));
                _grpcEndpoint = value;
            }
        }

        /// <summary>
        /// Overrides the HTTP endpoint used by <see cref="DaprClient" /> for communicating with the Dapr runtime.
        /// </summary>
        /// <remarks>
        ///     The URI endpoint to use for HTTP calls to the Dapr runtime. The default value will be
        ///     <c>http://127.0.0.1:DAPR_HTTP_PORT</c> where <c>DAPR_HTTP_PORT</c> represents the value of the
        ///     <c>DAPR_HTTP_PORT</c> environment variable.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string HttpEndpoint
        {
            get => _httpEndpoint;
            set
            {
                Guard.NotNullOrWhitespace(value, nameof(value));
                _httpEndpoint = value;
            }
        }

        /// <summary>
        /// Adds a API token on every request to the Dapr runtime.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string DaprApiToken
        {
            get => _daprApiToken;
            set
            {
                Guard.NotNullOrWhitespace(value, nameof(value));
                _daprApiToken = value;
            }
        }

        /// <summary>
        /// Gets or sets the flag to indicate whether or not the <see cref="DaprSecretProvider"/> should track the Dapr dependency.
        /// </summary>
        public bool TrackDependency { get; set; } = false;

        /// <summary>
        /// Adds an optional metadata entry which will be sent to the Dapr secret store.
        /// </summary>
        /// <param name="key">The unique metadata key.</param>
        /// <param name="value">The metadata value for the <paramref name="key"/>.</param>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="key"/> or <paramref name="value"/> is blank,
        ///     or when there already exists a metadata entry for the same <paramref name="key"/>.
        /// </exception>
        public void AddMetadata(string key, string value)
        {
            Guard.NotNullOrWhitespace(key, nameof(key));
            Guard.NotNullOrWhitespace(value, nameof(value));

            if (Metadata.ContainsKey(key))
            {
                throw new ArgumentException(
                    $"Cannot add metadata entry because there already exists an entry with key '{key}'", nameof(key));
            }

            Metadata.Add(key, value);
        }

        /// <summary>
        /// Creates an <see cref="DaprClient"/> based on the previously configured options.
        /// </summary>
        internal DaprClient CreateClient()
        {
            var builder = new DaprClientBuilder();

            if (!string.IsNullOrWhiteSpace(_grpcEndpoint))
            {
                builder.UseGrpcEndpoint(_grpcEndpoint);
            }

            if (!string.IsNullOrWhiteSpace(_daprApiToken))
            {
                builder.UseDaprApiToken(_daprApiToken);
            }

            if (!string.IsNullOrWhiteSpace(_httpEndpoint))
            {
                builder.UseHttpEndpoint(_httpEndpoint);
            }

            return builder.Build();
        }
    }
}
