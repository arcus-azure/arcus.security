﻿using System;
using System.Net;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Kubernetes;
using VaultSharp.V1.AuthMethods.UserPass;

namespace Arcus.Security.Providers.HashiCorp.Extensions
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to add the HashiCorp Vault as <see cref="ISecretProvider"/>.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="username">The username of the UserPass authentication method.</param>
        /// <param name="password">The password of the UserPass authentication method.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="secretPath"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="username"/> or <paramref name="password"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithUserPass(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string username,
            string password,
            string secretPath)
        {
            return AddHashiCorpVaultWithUserPass(builder, vaultServerUriWithPort, username, password, secretPath, configureOptions: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="username">The username of the UserPass authentication method.</param>
        /// <param name="password">The password of the UserPass authentication method.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="secretPath"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="username"/> or <paramref name="password"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithUserPass(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string username,
            string password,
            string secretPath,
            Action<HashiCorpVaultUserPassOptions> configureOptions)
        {
            return AddHashiCorpVaultWithUserPass(builder, vaultServerUriWithPort, username, password, secretPath, configureOptions, name: null, mutateSecretName: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="username">The username of the UserPass authentication method.</param>
        /// <param name="password">The password of the UserPass authentication method.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The optional function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="name">The unique name to register this HashiCorp provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="secretPath"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="username"/> or <paramref name="password"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithUserPass(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string username,
            string password,
            string secretPath,
            Action<HashiCorpVaultUserPassOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            if (string.IsNullOrWhiteSpace(vaultServerUriWithPort))
            {
                throw new ArgumentException("Requires a valid HashiCorp Vault URI with HTTP port to connect to the running HashiCorp Vault", nameof(vaultServerUriWithPort));
            }

            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Requires a username for the UserPass authentication during connecting with the HashiCorp Vault", nameof(username));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Requires a password for the UserPass authentication during connecting with the HashiCorp Vault", nameof(password));
            }

            if (string.IsNullOrWhiteSpace(secretPath))
            {
                throw new ArgumentException("Requires a path where the HashiCorp Vault secrets are stored", nameof(secretPath));
            }

            if (!Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("Requires a HashiCorp Vault server URI with HTTP port", nameof(vaultServerUriWithPort));
            }

            var options = new HashiCorpVaultUserPassOptions();
            configureOptions?.Invoke(options);

            IAuthMethodInfo authenticationMethod = new UserPassAuthMethodInfo(options.UserPassMountPoint, username, password);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions: secretProviderOptions =>
            {
                secretProviderOptions.Name = name;
                secretProviderOptions.MutateSecretName = mutateSecretName;
            });
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="roleName">
        ///     The name of the role in the Kubernetes authentication.
        ///     Role types have specific entities that can perform login operations against this endpoint.
        ///     Constraints specific to the role type must be set on the role. These are applied to the authenticated entities attempting to login.
        /// </param>
        /// <param name="jsonWebToken">The service account JWT used to access the TokenReview API to validate other JWTs during login.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="jsonWebToken"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithKubernetes(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string roleName,
            string jsonWebToken,
            string secretPath)
        {
            return AddHashiCorpVaultWithKubernetes(builder, vaultServerUriWithPort, roleName, jsonWebToken, secretPath, configureOptions: null, name: null, mutateSecretName: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="roleName">
        ///     The name of the role in the Kubernetes authentication.
        ///     Role types have specific entities that can perform login operations against this endpoint.
        ///     Constraints specific to the role type must be set on the role. These are applied to the authenticated entities attempting to login.
        /// </param>
        /// <param name="jsonWebToken">The service account JWT used to access the TokenReview API to validate other JWTs during login.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions"></param>
        /// <param name="name">The unique name to register this HashiCorp provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="jsonWebToken"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithKubernetes(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string roleName,
            string jsonWebToken,
            string secretPath,
            Action<HashiCorpVaultKubernetesOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            if (string.IsNullOrWhiteSpace(vaultServerUriWithPort))
            {
                throw new ArgumentException("Requires a valid HashiCorp Vault URI with HTTP port to connect to the running HashiCorp Vault", nameof(vaultServerUriWithPort));
            }

            if (string.IsNullOrWhiteSpace(jsonWebToken))
            {
                throw new ArgumentException("Requires a valid Json Web Token (JWT) during the Kubernetes authentication procedure", nameof(jsonWebToken));
            }

            if (string.IsNullOrWhiteSpace(secretPath))
            {
                throw new ArgumentException("Requires a path where the HashiCorp Vault secrets are stored", nameof(secretPath));
            }
            
            if (!Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("Requires a HashiCorp Vault server URI with HTTP port", nameof(vaultServerUriWithPort));
            }

            var options = new HashiCorpVaultKubernetesOptions();
            configureOptions?.Invoke(options);

            IAuthMethodInfo authenticationMethod = new KubernetesAuthMethodInfo(options.KubernetesMountPoint, roleName, jsonWebToken);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions: secretProviderOptions =>
            {
                secretProviderOptions.Name = name;
                secretProviderOptions.MutateSecretName = mutateSecretName;
            });
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> doesn't have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath)
        {
            return AddHashiCorpVault(builder, settings, secretPath, configureOptions: null, name: null, mutateSecretName: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="name">The unique name to register this HashiCorp provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> doesn't have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            Action<HashiCorpVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            var options = new HashiCorpVaultOptions();
            configureOptions?.Invoke(options);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions: secretProviderOptions =>
            {
                secretProviderOptions.Name = name;
                secretProviderOptions.MutateSecretName = mutateSecretName;
            });
        }
        
        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <typeparam name="TSecretProvider">The custom implementation type that implements the <see cref="HashiCorpSecretProvider"/>.</typeparam>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="implementationFactory">The factory function to create an implementation of the <see cref="HashiCorpSecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddHashiCorpVault<TSecretProvider>(
            this SecretStoreBuilder builder, 
            Func<IServiceProvider, TSecretProvider> implementationFactory)
            where TSecretProvider : HashiCorpSecretProvider
        {
            return AddHashiCorpVault(builder, implementationFactory, name: null, mutateSecretName: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <typeparam name="TSecretProvider">The custom implementation type that implements the <see cref="HashiCorpSecretProvider"/>.</typeparam>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="implementationFactory">The factory function to create an implementation of the <see cref="HashiCorpSecretProvider"/>.</param>
        /// <param name="name">The unique name to register this HashiCorp provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddHashiCorpVault<TSecretProvider>(
            this SecretStoreBuilder builder, 
            Func<IServiceProvider, TSecretProvider> implementationFactory,
            string name,
            Func<string, string> mutateSecretName)
            where TSecretProvider : HashiCorpSecretProvider
        {
            if (implementationFactory is null)
            {
                throw new ArgumentNullException(nameof(implementationFactory));
            }

            AddHashiCorpCriticalExceptions(builder);

            return builder.AddProvider(implementationFactory, options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }

        private static SecretStoreBuilder AddHashiCorpVault(
            SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            HashiCorpVaultOptions options,
            Action<SecretProviderOptions> configureSecretProviderOptions)
        {
            if (settings is null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            if (settings.AuthMethodInfo is null)
            {
                throw new ArgumentNullException(nameof(settings), "Requires a authentication method to connect to the HashiCorp Vault");
            }

            if (string.IsNullOrWhiteSpace(settings.VaultServerUriWithPort))
            {
                throw new ArgumentException("Requires a HashiCorp Vault server URI with HTTP port", nameof(settings));
            }

            if (!Uri.IsWellFormedUriString(settings.VaultServerUriWithPort, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("Requires a HashiCorp Vault server URI with HTTP port", nameof(settings));
            }

            AddHashiCorpCriticalExceptions(builder);

            return builder.AddProvider(serviceProvider =>
            {
                var logger = serviceProvider.GetService<ILogger<HashiCorpSecretProvider>>();
                var provider = new HashiCorpSecretProvider(settings, secretPath, options, logger);
                
                return provider;
            }, configureSecretProviderOptions);
        }

        private static void AddHashiCorpCriticalExceptions(SecretStoreBuilder builder)
        {
            // Thrown when the HashiCorp Vault's authentication and/or authorization fails.
            builder.AddCriticalException<VaultApiException>(exception =>
            {
                return exception.HttpStatusCode == HttpStatusCode.BadRequest
                       || exception.HttpStatusCode == HttpStatusCode.Forbidden;
            });
        }
    }
}
