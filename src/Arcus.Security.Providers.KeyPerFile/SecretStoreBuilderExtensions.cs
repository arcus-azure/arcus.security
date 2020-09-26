using Microsoft.Extensions.Configuration.KeyPerFile;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Providers.DockerSecrets
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddDockerSecrets(this SecretStoreBuilder builder, string directoryPath, bool optional = true)
        {
            KeyPerFileConfigurationSource configuration = new KeyPerFileConfigurationSource();

            configuration.FileProvider = new PhysicalFileProvider(directoryPath);
            configuration.Optional = optional;

            return builder.AddProvider(new DockerSecretsSecretProvider(configuration));
        }
    }
}
