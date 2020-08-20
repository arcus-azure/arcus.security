namespace Arcus.Security.Providers.HashiCorp
{
    /// <summary>
    /// Represents the API version of the client engines when interacting with the HashiCorp Vault in the <see cref="HashiCorpSecretProvider"/>.
    /// </summary>
    public enum VaultKeyValueSecretEngineVersion
    {
        /// <summary>
        /// Uses the <see cref="VaultSharp.V1.SecretsEngines.KeyValue.V1.IKeyValueSecretsEngineV1"/> when reading secrets in the <see cref="HashiCorpSecretProvider"/>.
        /// </summary>
        V1 = 1,

        /// <summary>
        /// Uses the <see cref="VaultSharp.V1.SecretsEngines.KeyValue.V2.IKeyValueSecretsEngineV2"/> when reading secrets in the <see cref="HashiCorpSecretProvider"/>.
        /// </summary>
        V2 = 2
    }
}