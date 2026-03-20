// @ts-check
const tseslint = require('typescript-eslint');
const prettierPlugin = require('eslint-plugin-prettier');
const prettierConfig = require('eslint-config-prettier');

module.exports = tseslint.config(
  {
    // Files to lint
    files: ['src/**/*.ts', 'test/**/*.ts'],

    // Base: typescript-eslint recommended rules
    extends: [
      ...tseslint.configs.recommended,
    ],

    plugins: {
      prettier: prettierPlugin,
    },

    languageOptions: {
      parserOptions: {
        project: 'tsconfig.eslint.json',
        tsconfigRootDir: __dirname,
      },
    },

    rules: {
      // Prettier formatting as lint errors
      'prettier/prettier': 'error',

      // Relax rules that conflict with NestJS patterns
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },

  // Disable ESLint rules that conflict with Prettier (must come last)
  prettierConfig,

  {
    // Never lint compiled output or deps
    ignores: ['dist/**', 'node_modules/**', 'coverage/**'],
  },
);
