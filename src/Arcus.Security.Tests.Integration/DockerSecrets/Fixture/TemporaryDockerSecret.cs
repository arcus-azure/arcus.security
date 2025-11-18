using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Arcus.Security.Tests.Integration.DockerSecrets.Fixture
{
    internal class TemporaryDockerSecret : IDisposable
    {
        private readonly string _secretName;
        private readonly ILogger _logger;

        private TemporaryDockerSecret(string secretName, string secretLocation, ILogger logger)
        {
            _secretName = secretName;
            _logger = logger;
            Location = secretLocation;
        }

        public string Location { get; }

        public static async Task<TemporaryDockerSecret> CreateNewAsync(string secretName, string secretValue, ILogger logger)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

            var secretLocation = Path.Combine(Path.GetTempPath(), "dockersecretstests");
            Directory.CreateDirectory(secretLocation);

            string secretPath = Path.Combine(secretLocation, secretName);
            logger.LogDebug("[Test:Setup] add Docker secret '{SecretName}' with value '{SecretValue}", secretName, secretValue);
            await File.WriteAllTextAsync(secretPath, secretValue);


            return new TemporaryDockerSecret(secretName, secretLocation, logger);
        }

        public void Dispose()
        {
            _logger.LogDebug("[Test:Teardown] remove Docker secret '{SecretName}'", _secretName);
            Directory.Delete(Location, true);
        }
    }
}
