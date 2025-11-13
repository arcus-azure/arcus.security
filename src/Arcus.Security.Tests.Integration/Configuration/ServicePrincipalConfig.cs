using System;
using Arcus.Testing;
using Azure.Core;
using Azure.Identity;

namespace Arcus.Security.Tests.Integration.Configuration
{
    /// <summary>
    /// Represents the test user service principal on Azure that has access to the deployed test resources.
    /// </summary>
    internal class ServicePrincipalConfig
    {
        private readonly string _tenantId, _clientId, _clientSecret;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServicePrincipalConfig"/> class.
        /// </summary>
        internal ServicePrincipalConfig(string tenantId, string clientId, string clientSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);

            _tenantId = tenantId;
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        /// <summary>
        /// Gets the <see cref="TokenCredential"/> representation of the current service principal.
        /// </summary>
        internal TokenCredential GetCredential()
        {
            return new ClientSecretCredential(_tenantId, _clientId, _clientSecret);
        }
    }

    internal static class ServicePrincipalTestConfigExtensions
    {
        /// <summary>
        /// Loads the <see cref="ServicePrincipalConfig"/> test configuration model from the current test <paramref name="config"/>.
        /// </summary>
        internal static ServicePrincipalConfig GetServicePrincipal(this TestConfig config)
        {
            return new ServicePrincipalConfig(
                config["Arcus:Tenant"],
                config["Arcus:ServicePrincipal:ApplicationId"],
                config["Arcus:ServicePrincipal:AccessKey"]);
        }
    }
}
