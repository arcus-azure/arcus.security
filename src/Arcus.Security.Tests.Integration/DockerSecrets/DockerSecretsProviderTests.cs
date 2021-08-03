using Arcus.Security.Providers.DockerSecrets;
using System;
using System.IO;
using Xunit;

namespace Arcus.Security.Tests.Integration.DockerSecrets
{
    public class DockerSecretsProviderTests
    {
        [Fact]
        public void Instantiate_WithRelativePath_Throws()
        {
            Assert.Throws<ArgumentException>(() => new DockerSecretsSecretProvider("./foo"));
        }

        [Fact]
        public void Instantiate_WithNonExistingSecretLocation_Throws()
        {
            Assert.Throws<DirectoryNotFoundException>(() => new DockerSecretsSecretProvider("/foo/bar"));
        }
    }
}
