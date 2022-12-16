('use strict');

// Original: https://github.com/sdras/night-owl-vscode-theme

var theme = {
  plain: {
    color: '#e9edfa',
    backgroundColor: '#19203d',
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
        color: 'hsl(5, 74%, 69%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['inserted', 'attr-name'],
      style: {
        color: 'hsl(119, 34%, 67%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['comment'],
      style: {
        color: 'hsl(230, 4%, 74%)',
        fontStyle: 'italic',
      },
    },
    {
      types: ['string', 'url'],
      style: {
        color: 'hsl(119, 34%, 67%)',
      },
    },
    {
      types: ['variable'],
      style: {
        color: '#47acff',
      },
    },
    {
      types: ['number'],
      style: {
        color: 'hsl(35, 99%, 66%)',
      },
    },
    {
      types: ['builtin', 'char', 'constant', 'function', 'operator'],
      style: {
        color: '#47acff',
      },
    },
    {
      // This was manually added after the auto-generation
      // so that punctuations are not italicised
      types: ['punctuation'],
      style: {
        color: '#e9edfa',
      },
    },
    {
      types: ['selector', 'doctype'],
      style: {
        color: '#e9edfa',
        fontStyle: 'italic',
      },
    },
    {
      types: ['class-name'],
      style: {
        color: 'hsl(35, 99%, 66%)',
      },
    },
    {
      types: ['tag', 'keyword'],
      style: {
        color: 'hsl(301, 63%, 80%)',
      },
    },
    {
      types: ['boolean'],
      style: {
        color: 'hsl(35, 99%, 66%)',
      },
    },
    {
      types: ['property'],
      style: {
        color: 'hsl(5, 74%, 69%)',
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
