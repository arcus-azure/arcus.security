# Website

This website is built using [Docusaurus 2](https://docusaurus.io/), a modern static website generator.

## Prerequisites
This documentation assumes that you run all scripts within the docs folder.

```console
cd docs
```


## Installation

```console
npm install
```

## Local Development

```console
npm start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Versioning
https://docusaurus.io/docs/versioning

You can use the version script to create a new documentation version based on the latest content in the `./preview` directory. That specific set of documentation will then be preserved and accessible even as the documentation in the docs directory changes moving forward.

### Tagging a new version

1. First, make sure your content in the `./preview` directory is ready to be frozen as a version. A version always should be based from master.
2. Enter a new version number: 
   
`npm run docusaurus docs:version 1.1.0`

---
When tagging a new version, the document versioning mechanism will:

- Copy the full `./preview` folder contents into a new `versioned_docs/version-<version>/` folder.
- Create a versioned sidebars file based from your current sidebar configuration (if it exists) - saved as `versioned_sidebars/version-<version>-sidebars.json`.
- Append the new version number to `versions.json`.

## Syntax higlighting

To have syntax highlighting within the codeblocks you have to use one of the prism supported languages:

https://github.com/FormidableLabs/prism-react-renderer/blob/master/src/vendor/prism/includeLangs.js
## Deploying to Netlify

https://docusaurus.io/docs/deployment#deploying-to-netlify
