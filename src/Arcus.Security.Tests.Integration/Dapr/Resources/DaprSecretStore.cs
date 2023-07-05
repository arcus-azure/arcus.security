namespace Arcus.Security.Tests.Integration.Dapr.Resources
{
    /// <summary>
    /// Represents the schema of the YAML file of the Dapr local secret store.
    /// </summary>
    public class DaprSecretStore
    {
        public string ApiVersion { get; set; }
        public string Kind { get; set; }
        public DaprSecretStoreMetaData Metadata { get; set; }
        public DaprSecretStoreSpec Spec { get; set; }
    }

    public class DaprSecretStoreMetaData
    {
        public string Name { get; set; }
        public string Namespace { get; set; }
    }

    public class DaprSecretStoreSpec
    {
        public string Type { get; set; }
        public string Version { get; set; }
        public DaprSecretStoreSpecMetaData[] Metadata { get; set; }
    }

    public class DaprSecretStoreSpecMetaData
    {
        public string Name { get; set; }
        public object Value { get; set; }
    }
}
