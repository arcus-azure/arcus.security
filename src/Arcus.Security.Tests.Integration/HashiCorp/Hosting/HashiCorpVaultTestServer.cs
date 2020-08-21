using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Tests.Integration.Fixture;
using GuardNet;
using Microsoft.Extensions.Logging;
using Vault;
using Vault.Endpoints;
using Vault.Endpoints.Sys;
using Vault.Models.Auth.UserPass;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines.KeyValue.V1;
using VaultSharp.V1.SecretsEngines.KeyValue.V2;
using IVaultClient = VaultSharp.IVaultClient;
using MountInfo = Arcus.Security.Tests.Integration.HashiCorp.Mounting.MountInfo;
using VaultClient = Vault.VaultClient;

namespace Arcus.Security.Tests.Integration.HashiCorp.Hosting
{
    /// <summary>
    /// Represents a HashiCorp Vault instance running in 'dev server' mode.
    /// </summary>
    public class HashiCorpVaultTestServer : IDisposable
    {
        private readonly Process _process;
        private readonly string _rootToken;
        private readonly ISysEndpoint _systemEndpoint;
        private readonly IEndpoint _authenticationEndpoint;
        private readonly ILogger _logger;

        private bool _disposed;

        private HashiCorpVaultTestServer(Process process, string rootToken, string listenAddress, ILogger logger)
        {
            Guard.NotNull(process, nameof(process));
            Guard.NotNullOrWhitespace(rootToken, nameof(rootToken));
            Guard.NotNullOrWhitespace(listenAddress, nameof(listenAddress));
            Guard.NotNull(logger, nameof(logger));

            _process = process;
            _rootToken = rootToken;
            _logger = logger;

            ListenAddress = new UriBuilder(listenAddress).Uri;
            var client = new VaultClient(ListenAddress, rootToken);
            _systemEndpoint = client.Sys;
            _authenticationEndpoint = client.Auth;

            var settings = new VaultClientSettings(ListenAddress.ToString(), new TokenAuthMethodInfo(rootToken));
            IVaultClient testClient = new VaultSharp.VaultClient(settings);
            KeyValueV1 = testClient.V1.Secrets.KeyValue.V1;
            KeyValueV2 = testClient.V1.Secrets.KeyValue.V2;
        }

        /// <summary>
        /// Gets the URI where the HashiCorp Vault test server is listening on.
        /// </summary>
        public Uri ListenAddress { get; }

        /// <summary>
        /// Gets the KeyValue V2 secret engine to control the secret store in the HashiCorp Vault.
        /// </summary>
        public IKeyValueSecretsEngineV1 KeyValueV1 { get; }

        /// <summary>
        /// Gets the KeyValue V2 secret engine to control the secret store in the HashiCorp Vault.
        /// </summary>
        public IKeyValueSecretsEngineV2 KeyValueV2 { get; }

        /// <summary>
        /// Starts a new instance of the <see cref="HashiCorpVaultTestServer"/> using the 'dev server' settings, meaning the Vault will run fully in-memory.
        /// </summary>
        /// <param name="configuration">The configuration instance to retrieve the HashiCorp installation folder ('Arcus.HashiCorp.VaultBin').</param>
        /// <param name="logger">The instance to log diagnostic trace messages during the lifetime of the test server.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configuration"/> or <paramref name="logger"/> is <c>null</c>.</exception>
        public static async Task<HashiCorpVaultTestServer> StartServerAsync(TestConfig configuration, ILogger logger)
        {
            Guard.NotNull(logger, nameof(logger), 
                "Requires a logger for logging diagnostic trace messages during the lifetime of the test server");
            Guard.NotNull(configuration, nameof(configuration),
                "Requires a configuration instance to retrieve the HashiCorp Vault installation folder");

            var rootToken = Guid.NewGuid().ToString();
            int port = GetRandomUnusedPort();
            string listenAddress = $"127.0.0.1:{port}";
            string vaultArgs = String.Join(" ", new List<string>
            {
                "server",
                "-dev",
                $"-dev-root-token-id={rootToken}",
                $"-dev-listen-address={listenAddress}"
            });

            FileInfo vaultFile = configuration.GetHashiCorpVaultBin();
            var startInfo = new ProcessStartInfo(vaultFile.FullName, vaultArgs)
            {
                WorkingDirectory = Directory.GetCurrentDirectory(),
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };

            startInfo.EnvironmentVariables["HOME"] = Directory.GetCurrentDirectory();
            var process = new Process { StartInfo = startInfo };
            process.ErrorDataReceived += (sender, args) => logger.LogError(args.Data);

            try
            {
                await StartHashiCorpVaultAsync(process, listenAddress, logger);
                return new HashiCorpVaultTestServer(process, rootToken, listenAddress, logger);
            }
            catch (Exception exception)
            {
                var message = "An unexpected problem occured while trying to start the HashiCorp Vault";
                logger.LogError(exception, message);
                
                throw new CouldNotStartHashiCorpVaultException(message, exception);
            }
            finally
            {
                process?.Dispose();
            }
        }

        private static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Any, 0);
            listener.Start();
            int port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();
            
            return port;
        }

        private static async Task StartHashiCorpVaultAsync(Process process, string listenAddress, ILogger logger)
        {
            logger.LogTrace("Starting HashiCorp Vault at '{listenAddress}'...", listenAddress);

            if (!process.Start())
            {
                throw new CouldNotStartHashiCorpVaultException($"Process did not start successfully: {process.StandardError}");
            }

            process.BeginErrorReadLine();

            var isStarted = false;

            string line = await process.StandardOutput.ReadLineAsync();
            while (line != null)
            {
                logger.LogTrace(line);
                if (line?.StartsWith("==> Vault server started!") == true)
                {
                    isStarted = true;
                    break;
                }

                line = await process.StandardOutput.ReadLineAsync();
            }

            if (!isStarted)
            {
                throw new CouldNotStartHashiCorpVaultException("Process did not start successfully");
            }

            logger.LogInformation("HashiCorp Vault started at '{ListenAddress}'", listenAddress);
        }

        /// <summary>
        /// Mounts the KeyValue secret engine with a specific <paramref name="version"/> to a specific <paramref name="path"/>.
        /// </summary>
        /// <param name="path">The path to mount the secret engine to.</param>
        /// <param name="version">The version of the KeyValue secret engine to mount.</param>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="path"/> is blank or the <paramref name="version"/> is outside the bounds of the enumeration.
        /// </exception>
        public async Task MountKeyValueAsync(string path, VaultKeyValueSecretEngineVersion version)
        {
            Guard.NotNullOrWhitespace(path, nameof(path), "Requires a path to mount the KeyValue secret engine to");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), version), "Requires a KeyValue secret engine version that is either V1 or V2");

            var content = new MountInfo
            {
                Type = "kv",
                Description = "KeyValue v1 secret engine",
                Options = new MountOptions { Version = ((int) version).ToString() }
            };

            var http = new VaultHttpClient();
            var uri = new Uri(ListenAddress, "/v1/sys/mounts/" + path);
            await http.PostVoid(uri, content, _rootToken, default(CancellationToken));
        }

        /// <summary>
        /// Adds a new authorization policy to the running HashiCorp Vault.
        /// </summary>
        /// <param name="name">The name to identify the policy.</param>
        /// <param name="path">The path where this policy will be applicable.</param>
        /// <param name="capabilities">The capabilities that should be available in the policy.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/>, <paramref name="path"/>, or any of the <paramref name="capabilities"/> is blank.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="capabilities"/> is <c>null</c>.</exception>
        public async Task AddPolicyAsync(string name, string path, string[] capabilities)
        {
            Guard.NotNullOrWhitespace(name, nameof(name), "Requires a name to identify the policy");
            Guard.NotNullOrWhitespace(path, nameof(path), "Requires a path where the policy will be applicable");
            Guard.NotNull(capabilities, nameof(capabilities), "Requires a set of capabilities that should be available in this policy");
            Guard.NotAny(capabilities, nameof(capabilities), "Requires a set of capabilities that should be available in this policy");
            Guard.For<ArgumentException>(() => capabilities.Any(String.IsNullOrWhiteSpace), "Requires all the capabilities of the policy to be filled out (not blank)");

            string joinedCapabilities = String.Join(", ", capabilities.Select(c => $"\"{c}\""));
            string rules = $"path \"{path}/*\" {{  capabilities = [ {joinedCapabilities} ]}}";
            
            await _systemEndpoint.PutPolicy(name, rules);
        }

        /// <summary>
        /// Enables an authentication type on the HashiCorp Vault.
        /// </summary>
        /// <param name="type">The type of the authentication to enable.</param>
        /// <param name="description">The optional message that describes the authentication type (for user friendliness).</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="type"/> is blank.</exception>
        public async Task EnableAuthenticationTypeAsync(string type, string description)
        {
            Guard.NotNullOrWhitespace(type, nameof(type), "Requires an authentication type to enable the authentication");

            await _systemEndpoint.EnableAuth(path: type, authType: type, description: description);
        }

        /// <summary>
        /// Adds a user to the UserPass authentication in HashiCorp Vault, related to a specific path
        /// and only be able to do the capabilities defined in the policy with the <paramref name="policyName"/>.
        /// </summary>
        /// <param name="username">The username of the user.</param>
        /// <param name="password">The password of the user.</param>
        /// <param name="policyName">The name of the policy the user will be capable to do.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="username"/>, <paramref name="password"/>, or <paramref name="policyName"/> is blank.</exception>
        public async Task AddUserPassUserAsync(string username, string password, string policyName)
        {
            Guard.NotNullOrWhitespace(username, nameof(username));
            Guard.NotNullOrWhitespace(password, nameof(password));
            Guard.NotNullOrWhitespace(policyName, nameof(policyName));

            await _authenticationEndpoint.Write($"/userpass/users/{username}", new UsersRequest
            {
                Password = password,
                Policies = new List<string> { policyName }
            });
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                try
                {
                    if (_process.HasExited)
                    {
                        _process.Kill();
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogError(exception, "Failure during stopping of the HashiCorp Vault");
                }
            }

            _disposed = true;
        }
    }
}
