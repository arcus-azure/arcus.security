('use strict');

// Original: https://github.com/sdras/night-owl-vscode-theme

var theme = {
  plain: {
    color: '#19203d',
    backgroundColor: '#f6f8fa',
  },
  styles: [
    {
      types: ['changed'],
      style: {
        color: 'rgb(162, 191, 252)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['deleted'],
      style: {
        color: 'hsl(5, 74%, 59%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['inserted', 'attr-name'],
      style: {
        color: 'hsl(119, 34%, 47%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['comment'],
      style: {
        color: 'hsl(230, 4%, 64%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['string', 'url'],
      style: {
        color: 'hsl(119, 34%, 47%)',
      },
    },
    {
      types: ['variable'],
      style: {
        color: '#249cff',
      },
    },
    {
      types: ['number'],
      style: {
        color: 'hsl(35, 99%, 36%)',
      },
    },
    {
      types: ['builtin', 'char', 'constant', 'function', 'operator'],
      style: {
        color: '#249cff',
      },
    },
    {
      // This was manually added after the auto-generation
      // so that punctuations are not italicised
      types: ['punctuation'],
      style: {
        color: '#19203d',
      },
    },
    {
      types: ['selector', 'doctype'],
      style: {
        color: '#19203d',
        fontStyle: 'italic',
      },
    },
    {
      types: ['class-name'],
      style: {
        color: 'hsl(35, 99%, 36%)',
      },
    },
    {
      types: ['tag', 'keyword'],
      style: {
        color: 'hsl(301, 63%, 40%)',
      },
    },
    {
      types: ['boolean'],
      style: {
        color: 'hsl(35, 99%, 36%)',
      },
    },
    {
      types: ['property'],
      style: {
        color: 'hsl(5, 74%, 59%)',
      },
    },
    {
      types: ['namespace'],
      style: {
        opacity: 0.8,
      },
    },
  ],
};

module.exports = theme;
