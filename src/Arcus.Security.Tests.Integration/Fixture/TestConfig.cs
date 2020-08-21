using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using GuardNet;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// Represents the configuration used in the integration test suite.
    /// </summary>
    public class TestConfig : IConfiguration
    {
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Prevents a new instance of the <see cref="TestConfig"/> class from being created.
        /// </summary>
        private TestConfig(IConfiguration configuration)
        {
            Guard.NotNull(configuration, nameof(configuration), $"Requires an {nameof(IConfiguration)} instance to initialize the test config");

            _configuration = configuration;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="TestConfig"/> class.
        /// </summary>
        public static TestConfig Create()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false)
                .Build();

            return new TestConfig(configuration);
        }

        /// <summary>
        /// Gets the configured HashiCorp Vault execution file.
        /// </summary>
        public FileInfo GetHashiCorpVaultBin()
        {
            const string key = "Arcus.HashiCorp.VaultBin";
            string vaultBin = _configuration[key];

            if (String.IsNullOrWhiteSpace(vaultBin))
            {
                throw new KeyNotFoundException(
                    $"Could not find HashiCorp Vault execution file for key: '{key}', was blank");
            }

            FileInfo vaultFile;
            try
            {
                vaultFile = new FileInfo(vaultBin);
            }
            catch (Exception exception)
            {
                throw new FileNotFoundException(
                    $"File path returned for key '{key}' doesn't point to valid HashiCorp vault execution file", exception);
            }

            if (!vaultFile.Exists || vaultFile.Name != "vault.exe")
            {
                throw new FileNotFoundException(
                    $"File path returned for key '{key}' doesn't point to valid HashiCorp vault execution file");
            }

            return vaultFile;
        }

        /// <summary>
        /// Gets a configuration sub-section with the specified key.
        /// </summary>
        /// <param name="key">The key of the configuration section.</param>
        /// <returns>The <see cref="T:Microsoft.Extensions.Configuration.IConfigurationSection" />.</returns>
        /// <remarks>
        ///     This method will never return <c>null</c>. If no matching sub-section is found with the specified key,
        ///     an empty <see cref="T:Microsoft.Extensions.Configuration.IConfigurationSection" /> will be returned.
        /// </remarks>
        public IConfigurationSection GetSection(string key)
        {
            return _configuration.GetSection(key);
        }

        /// <summary>
        /// Gets the immediate descendant configuration sub-sections.
        /// </summary>
        /// <returns>The configuration sub-sections.</returns>
        public IEnumerable<IConfigurationSection> GetChildren()
        {
            return _configuration.GetChildren();
        }

        /// <summary>
        /// Returns a <see cref="T:Microsoft.Extensions.Primitives.IChangeToken" /> that can be used to observe when this configuration is reloaded.
        /// </summary>
        /// <returns>A <see cref="T:Microsoft.Extensions.Primitives.IChangeToken" />.</returns>
        public IChangeToken GetReloadToken()
        {
            return _configuration.GetReloadToken();
        }

        /// <summary>Gets or sets a configuration value.</summary>
        /// <param name="key">The configuration key.</param>
        /// <returns>The configuration value.</returns>
        public string this[string key]
        {
            get => _configuration[key];
            set => _configuration[key] = value;
        }
    }
}
