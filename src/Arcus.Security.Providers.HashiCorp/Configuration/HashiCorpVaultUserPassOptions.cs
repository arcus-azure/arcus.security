﻿using System;
using VaultSharp.V1.AuthMethods;

namespace Arcus.Security.Providers.HashiCorp.Configuration
{
    /// <summary>
    /// Represents the available options to configure the <see cref="HashiCorpSecretProvider"/> when using the UserPass authentication.
    /// </summary>
    public class HashiCorpVaultUserPassOptions : HashiCorpVaultOptions
    {
        private string _userPassMountPoint = AuthMethodDefaultPaths.UserPass;

        /// <summary>
        /// <para>Gets or sets the point where the HashiCorp Vault UserPass authentication is mounted.</para>
        /// <para>default: userpass </para>
        /// </summary>
        public string UserPassMountPoint
        {
            get => _userPassMountPoint;
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("Requires a non-blank mount point for the UserPass authentication", nameof(value));
                }

                _userPassMountPoint = value;
            }
        }
    }
}
