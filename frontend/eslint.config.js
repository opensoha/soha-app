import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'bindings/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.es2022 },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-undef': 'off',
      'react-hooks/rules-of-hooks': 'error',
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/native/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/bindings/**', '**/wailsjs/**', '@wailsio/**', '@wailsapp/**'],
              message: 'Import Wails bindings through src/native only.',
            },
            {
              group: ['**/soha-web/**'],
              message: 'Soha App must not import soha-web source.',
            },
          ],
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.object.name='window'][callee.property.name='open']",
          message: 'Open approved external URLs through the native facade.',
        },
        {
          selector: "CallExpression[callee.object.type='MemberExpression'][callee.object.object.name='window'][callee.object.property.name='location'][callee.property.name='assign']",
          message: 'Top-level WebView navigation is not allowed.',
        },
        {
          selector: "CallExpression[callee.object.name='location'][callee.property.name='assign']",
          message: 'Top-level WebView navigation is not allowed.',
        },
        {
          selector: "AssignmentExpression[left.object.name='window'][left.property.name='location']",
          message: 'Top-level WebView navigation is not allowed.',
        },
        {
          selector: "JSXAttribute[name.name='href']",
          message: 'Use App routes or the native facade instead of renderer links.',
        },
        {
          selector: "JSXAttribute[name.name='target']",
          message: 'New WebView windows are not allowed.',
        },
      ],
    },
  },
  {
    files: ['src/native/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/soha-web/**'],
              message: 'Soha App must not import soha-web source.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['*.config.js', '*.config.ts', 'eslint.config.js'],
    languageOptions: { globals: { ...globals.node, ...globals.es2022 } },
  },
)
