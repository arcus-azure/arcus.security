# Runnning integration tests with Arcus

We provide some testing infrastructure that allows you to run integration tests on top of Azure Key Vault.

## Azure Infrastructure

An Azure Active Directory (AD) App is required to be created. 
The **Application Id/Client Id** and **Application Secret/Access Key** should be set as environment variables.



<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Farcus-azure%2Farcus.security%2Fmaster%2Fdeploy%2Farm%2Fazuredeploy.json" target="_blank">
    <img src="https://azuredeploy.net/deploybutton.png"/>
</a>

## Local Environment

Configure the following environment variables:
* `Arcus__KeyVault__Uri`: The URI where the vault is located.
* `Arcus__KeyVault__TestKeyName`: The name of a secret in your Key Vault that will be used throughout the tests.
* `Arcus__ServicePrincipal__ClientId`: Object id of the Azure AD Application.
* `Arcus__ServicePrincipal__AccessKey`: Secret of the Azure AD Application.

Once you have completed the above, you can run `dotnet test` from the `src\Arcus.Security.Tests.Integration` directory.

---------

:pencil: _**Notes**_

- _If you are using Visual Studio, you must restart Visual Studio in order to use new Environment Variables._
- _`src\Arcus.Security.Tests.Integration\appsettings.json` can also be overriden but it brings the risk of commiting these changes. **This approach is not recommended.** This is also why we don't use `appsettings.{Environment}.json`_

---------