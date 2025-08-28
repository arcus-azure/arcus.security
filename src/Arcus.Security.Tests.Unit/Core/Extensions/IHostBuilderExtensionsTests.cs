using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Arcus.Testing;
using Arcus.Testing.Security.Providers.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;
using Xunit.Sdk;

namespace Arcus.Security.Tests.Unit.Core.Extensions
{
    public class IHostBuilderExtensionsTests
    {
        [Fact]
        public void ConfigureSecretStore_WithoutFoundLazySecretProvider_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => null));

            // Assert
            IHost host = builder.Build();
            Assert.Throws<InvalidOperationException>(() => host.Services.GetService<ISecretProvider>());
        }

        [Fact]
        public void ConfigureSecretStore_WithFailedLazySecretProviderCreation_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(serviceProvider => throw new TestClassException("Some failure"));
            });

            // Assert
            IHost host = builder.Build();
            Assert.Throws<TestClassException>(() => host.Services.GetService<ISecretProvider>());
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutSecretProviders_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => { });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutFoundSecretProvider_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();
            var emptyProvider = new InMemorySecretProvider();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(emptyProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithFoundLazyCachedSecretProvider_UsesLazyRegisteredSecretProvider()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new TestSecretProviderStub(expected);

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            string actual = await provider.GetRawSecretAsync("ignored-key");
            Assert.Equal(expected, actual);
            Assert.Equal(1, stubProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddInMemorySecretProvider_UsesInMemorySecretsInSecretStore()
        {
            // Arrange
            const string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey] = secretValue });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
            Assert.NotNull(host.Services.GetService<ICachedSecretProvider>());
        }

        [Fact]
        public async Task ConfigureSecretStore_AddMultipleSecretProviders_UsesAllSecretStores()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey1] = secretValue1 });

            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey2] = secretValue2 });

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey3] = secretValue3 });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((context, config, stores) =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(stubProvider2);
            }).ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider3));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await provider.GetRawSecretAsync(secretKey3));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddMultipleLazySecretProviders_UsesAllSecretProviders()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey1] = secretValue1 });

            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey2] = secretValue2 });

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey3] = secretValue3 });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((context, config, stores) =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(serviceProvider => stubProvider2);
            }).ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => stubProvider3));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await provider.GetRawSecretAsync(secretKey3));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingProviderWithOptionsMutation_DoesFindCachedProvider()
        {
            // Arrange
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { ["Arcus.KeyVault.Secret"] = expected });
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, options => options.MutateSecretName = secretName => "Arcus." + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await cachedSecretProvider.GetSecretAsync("KeyVault.Secret", ignoreCache: false);
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithSpecificCriticalException_ThrowsCriticalExceptionWhenThrownInSecretProvider()
        {
            // Arrange
            var stubProvider = new SaboteurSecretProvider(new AuthenticationException("Some authentication failure"));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<AuthenticationException>()
                      .AddProvider(stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<AuthenticationException>(() => provider.GetRawSecretAsync("some secret name"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithInvalidExceptionFilter_CatchesGeneral()
        {
            // Arrange
            var stubProvider = new InMemorySecretProvider();
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<CryptographicException>(
                    ex => throw new Exception("Throw something to let the exception filter fail"));

                stores.AddProvider(stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync("some secret name"));
        }

        [Fact]
        public void ConfigureSecretStore_WithoutExceptionFilter_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<AuthenticationException>(exceptionFilter: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public async Task ConfigureSecretStore_WithLazyCachedSecretProvider_FindsInvalidateSecret()
        {
            // Arrange
            var secretKey = "Arcus.KeyVault.Secret";
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { [secretKey] = expected });
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(serviceProvider => stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await cachedSecretProvider.GetSecretAsync(secretKey, ignoreCache: false);
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithDefaultAuditing_DoesntLogsSecurityEvent()
        {
            // Arrange
            string secretName = "MySecret";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = $"secret-{Guid.NewGuid()}" });
            var spyLogger = new InMemoryLogger();
            var builder = new HostBuilder();
            builder.ConfigureLogging(logging => logging.AddProvider(new CustomLoggerProvider(spyLogger)));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();
            await secretProvider.GetRawSecretAsync(secretName);
            Assert.DoesNotContain(spyLogger.Messages, msg => msg.StartsWith("Get Secret"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ConfigureSecretStore_WithAuditing_LogsSecurityEvent(bool emitSecurityEvents)
        {
            // Arrange
            string secretName = "MySecret";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = $"secret-{Guid.NewGuid()}" });
            var spyLogger = new InMemoryLogger();
            var builder = new HostBuilder();
            builder.ConfigureLogging(logging => logging.AddProvider(new CustomLoggerProvider(spyLogger)));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider)
                      .WithAuditing(options => options.EmitSecurityEvents = emitSecurityEvents);
            });

            // Assert
            IHost host = builder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();
            await secretProvider.GetRawSecretAsync(secretName);
            Assert.Equal(emitSecurityEvents, spyLogger.Messages.Count(msg => msg.StartsWith("Get Secret")) == 1);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithAuditingIncrement_LogsSecurityEvent()
        {
            // Arrange
            string secretName = "MySecret";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = $"secret-{Guid.NewGuid()}" });
            var spyLogger = new InMemoryLogger();
            var builder = new HostBuilder();
            builder.ConfigureLogging(logging => logging.AddProvider(new CustomLoggerProvider(spyLogger)));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider)
                      .WithAuditing(options => options.EmitSecurityEvents = false)
                      .WithAuditing(options => options.EmitSecurityEvents = true);
            });

            // Assert
            IHost host = builder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();
            await secretProvider.GetRawSecretAsync(secretName);
            Assert.Equal(1, spyLogger.Messages.Count(msg => msg.StartsWith("Get Secret")));
        }

        [Fact]
        public void ConfigureSecretStore_WithNamedProvider_RetrievedCorrectProvider()
        {
            // Arrange
            var name = $"provider-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider();
            var stubProvider2 = new InMemorySecretProvider();
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider1, options => options.Name = name)
                      .AddProvider(stubProvider2);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                Assert.Same(stubProvider1, store.GetProvider(name));
                Assert.Same(stubProvider1, store.GetProvider<ISyncSecretProvider>(name));
                Assert.Same(stubProvider1, store.GetProvider<InMemorySecretProvider>(name));

                Assert.NotSame(stubProvider2, store.GetProvider(name));
                Assert.NotSame(stubProvider2, store.GetProvider<ISyncSecretProvider>(name));
                Assert.NotSame(stubProvider2, store.GetProvider<InMemorySecretProvider>(name));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithNamedCachedProvider_RetrievedCorrectProvider()
        {
            // Arrange
            var name = $"provider-{Guid.NewGuid()}";
            var stubProvider1 = new InMemoryCachedSecretProvider();
            var stubProvider2 = new InMemoryCachedSecretProvider();
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider1, options => options.Name = name)
                      .AddProvider(stubProvider2);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                Assert.Same(stubProvider1, store.GetCachedProvider(name));
                Assert.Same(stubProvider1, store.GetCachedProvider<InMemoryCachedSecretProvider>(name));

                Assert.NotSame(stubProvider2, store.GetCachedProvider(name));
                Assert.NotSame(stubProvider2, store.GetCachedProvider<InMemoryCachedSecretProvider>(name));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithoutNamedProvider_Fails()
        {
            // Arrange
            var stubProvider1 = new InMemoryCachedSecretProvider();
            var stubProvider2 = new InMemoryCachedSecretProvider();
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider1)
                      .AddProvider(stubProvider2);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                Assert.Throws<KeyNotFoundException>(() => store.GetCachedProvider("some ignored name"));
                Assert.Throws<KeyNotFoundException>(() => store.GetCachedProvider<InMemoryCachedSecretProvider>("some ignored name"));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithUniqueNames_Succeeds()
        {
            // Arrange
            var name1 = $"name-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider();
            var name2 = $"name-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider();

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider1, options => options.Name = name1)
                      .AddProvider(stubProvider2, options => options.Name = name2);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var secretStore = host.Services.GetRequiredService<ISecretStore>();
                Assert.Same(stubProvider1, secretStore.GetProvider(name1));
                Assert.Same(stubProvider2, secretStore.GetProvider<InMemorySecretProvider>(name2));
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_WithDuplicateNames_MakesSubsetOfDuplicateSecretProviderNames()
        {
            // Arrange
            var name = $"duplicate-name-{Guid.NewGuid()}";
            string secretName1 = "MySecret-1", secretName2 = "My-Secret2", secretName3 = "My-Secret3", secretName4 = $"My-Secret4";
            string secretValue1 = $"secret-{Guid.NewGuid()}",
                   secretValue2 = $"secret-{Guid.NewGuid()}",
                   secretValue3 = $"secret-{Guid.NewGuid()}",
                   secretValue4 = $"secret-{Guid.NewGuid()}";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemorySecretProvider(new Dictionary<string, string> { [secretName1] = secretValue1 }), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider(new Dictionary<string, string> { [secretName3] = secretValue3 }), options => options.Name = "some other name")
                      .AddProvider(new InMemoryCachedSecretProvider(new Dictionary<string, string> { [secretName2] = secretValue2 }), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider(new Dictionary<string, string> { [secretName4] = secretValue4 }));
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                ISecretProvider provider = store.GetProvider(name);
                Assert.IsNotType<InMemoryCachedSecretProvider>(provider);
                Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretName1));
                Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretName2));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName3));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName4));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithDuplicateNames_FailsWhenRetrievingTypedSecretProvider()
        {
            // Arrange
            string name = $"duplicate-name-{Guid.NewGuid()}";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemorySecretProvider(), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider(), options => options.Name = name);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                Assert.NotNull(store.GetProvider<ISyncSecretProvider>(name));
                Assert.Throws<InvalidOperationException>(() => store.GetProvider<InMemorySecretProvider>(name));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithDuplicateNames_FailsWhenRetrievingTypedCachedSecretProvider()
        {
            // Arrange
            string name = $"duplicate-name-{Guid.NewGuid()}";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemoryCachedSecretProvider(), options => options.Name = name)
                      .AddProvider(new InMemoryCachedSecretProvider(), options => options.Name = name);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var store = host.Services.GetRequiredService<ISecretStore>();
                Assert.NotNull(store.GetProvider(name));
                Assert.NotNull(store.GetProvider<ISyncSecretProvider>(name));
                Assert.NotNull(store.GetProvider<IVersionedSecretProvider>(name));
                Assert.Throws<InvalidOperationException>(() => store.GetCachedProvider<InMemoryCachedSecretProvider>(name));
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_WithSyncSecretProvider_OnlyUsesSyncProviderWhenSynchronouslyRetrievingSecret()
        {
            // Arrange
            var builder = new HostBuilder();
            string secretValueAsync = Guid.NewGuid().ToString();
            string secretValueSync = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new AsyncStaticSecretProvider(secretValueAsync))
                      .AddEnvironmentVariables()
                      .AddProvider(new SyncStaticSecretProvider(secretValueSync));
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var asyncProvider = host.Services.GetRequiredService<ISecretProvider>();
                var syncProvider = host.Services.GetRequiredService<ISyncSecretProvider>();

                Assert.Equal(secretValueSync, syncProvider.GetRawSecret("Some.Secret"));
                Assert.Equal(secretValueSync, syncProvider.GetSecret("Some.Secret").Value);
                Assert.Equal(secretValueSync, asyncProvider.GetRawSecret("Some.Secret"));
                Assert.Equal(secretValueSync, asyncProvider.GetSecret("Some.Secret").Value);

                Assert.Equal(secretValueAsync, await asyncProvider.GetRawSecretAsync("Some.Secret"));
                Assert.Equal(secretValueAsync, (await asyncProvider.GetSecretAsync("Some.Secret")).Value);
                Assert.Equal(secretValueAsync, await syncProvider.GetRawSecretAsync("Some.Secret"));
                Assert.Equal(secretValueAsync, (await syncProvider.GetSecretAsync("Some.Secret")).Value);
            }
        }

        [Fact]
        public void GetRawSecret_FromOneSyncSecretProvider_Succeeds()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(new AsyncStaticSecretProvider(Guid.NewGuid().ToString()))
                      .AddProvider(new SyncStaticSecretProvider(Guid.NewGuid().ToString()))
                      .AddHashiCorpVault(new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("user", "pass")), "/path");
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.NotNull(secretProvider.GetRawSecret("Some.Secret"));
        }

        [Fact]
        public void GeSecret_FromOneSyncSecretProvider_Succeeds()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddHashiCorpVault(new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("user", "pass")), "/path")
                      .AddProvider(new SyncStaticSecretProvider(Guid.NewGuid().ToString()))
                      .AddProvider(new AsyncStaticSecretProvider(Guid.NewGuid().ToString()));
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.NotNull(secretProvider.GetSecret("Some.Secret"));
        }
    }
}
