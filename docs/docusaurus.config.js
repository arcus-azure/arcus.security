const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'Arcus - Security',
  url: 'https://security.arcus-azure.net/',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/arcus.png',
  organizationName: 'arcus-azure', // Usually your GitHub org/user name.
  projectName: 'Arcus - Security', // Usually your repo name.
  themeConfig: {
    algolia: {
      apiKey: process.env.ALGOLIA_API_KEY,
      indexName: 'arcus-azure',
      // Set `contextualSearch` to `true` when having multiple versions!!!
      contextualSearch: true,
      searchParameters: {
        facetFilters: ["tags:security"]
      },
    },
    image: 'img/arcus.jpg',
    navbar: {
      title: 'Security',
      logo: {
        alt: 'Arcus',
        src: 'img/arcus.png',
        srcDark: 'img/arcus.png'
      },
      items: [
        {
          type: 'docsVersionDropdown',

          //// Optional
          position: 'right',
          // Add additional dropdown items at the beginning/end of the dropdown.
          dropdownItemsBefore: [],
          // Do not add the link active class when browsing docs.
          dropdownActiveClassDisabled: true,
          docsPluginId: 'default',
        },
        {
          type: 'search',
          position: 'right',
        },
        {
          href: 'https://github.com/arcus-azure/arcus.security',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Community',
          items: [
            {
              label: 'Arcus Azure Github',
              href: 'https://github.com/arcus-azure',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()}, Arcus - Security maintained by arcus-azure`,
    },
    prism: {
      theme: lightCodeTheme,
      darkTheme: darkCodeTheme,
      additionalLanguages: ['csharp'],
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/',
          path: 'preview',
          sidebarCollapsible: false,
          // Please change this to your repo.
          editUrl:
            'https://github.com/arcus-azure/arcus.security/edit/master/docs',
          includeCurrentVersion: process.env.CONTEXT !== 'production',
          sidebarItemsGenerator: async function ({
                                                   defaultSidebarItemsGenerator,
                                                   ...args
                                                 }) {
            const sidebarItems = await defaultSidebarItemsGenerator(args);
            const capitalizeLabels = (items) => {
              return items?.map(item => ({
                ...item,
                label: item.label?.charAt(0).toUpperCase() + item.label?.slice(1),
                items: item.items ? capitalizeLabels(item.items) : null
              }));
            }

            return capitalizeLabels(sidebarItems)
          }
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],

};
