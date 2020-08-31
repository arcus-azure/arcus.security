namespace Arcus.Security.Providers.HashiCorp
{
    /// <summary>
    /// <para>Represents the version of the KeyValue secret engines when interacting with the HashiCorp Vault in the <see cref="HashiCorpSecretProvider"/>.</para>
    /// <para>See the official HashiCorp Vault docs: https://www.vaultproject.io/docs/secrets/kv for more information on this subject.</para>
    /// </summary>
    public enum VaultKeyValueSecretEngineVersion
    {
        /// <summary>
        /// <para>Uses the KeyValue V1 secret engine <see cref="VaultSharp.V1.SecretsEngines.KeyValue.V1.IKeyValueSecretsEngineV1"/> when reading secrets in the <see cref="HashiCorpSecretProvider"/>.</para>
        /// <para>See the HashiCorp Vault docs: https://www.vaultproject.io/docs/secrets/kv/kv-v1 for more information on this version of the secret engine.</para>
        /// </summary>
        V1 = 1,

        /// <summary>
        /// <para>Uses the KeyValue V! secret engine <see cref="VaultSharp.V1.SecretsEngines.KeyValue.V2.IKeyValueSecretsEngineV2"/> when reading secrets in the <see cref="HashiCorpSecretProvider"/>.</para>
        /// <para>See the HashiCorp Vault docs: https://www.vaultproject.io/docs/secrets/kv/kv-v2 for more information on this version of the secret engine.</para>
        /// </summary>
        V2 = 2
    }
}