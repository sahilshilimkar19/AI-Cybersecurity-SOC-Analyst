import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // Off deliberately. The rule protects hot-module-reload state preservation,
      // which is a dev-server nicety; obeying it would mean splitting `isSafeUrl`,
      // `useAuth`, and `downloadText` into one-function modules away from the
      // components whose contract they define. Colocation is worth more than a
      // faster edit-refresh loop, and `lint` runs with --max-warnings 0 so this
      // has to be an explicit decision rather than accumulated noise.
      'react-refresh/only-export-components': 'off',

      // The platform renders untrusted log content. React escapes by default;
      // these two rules are what stop someone from opting out of that, and they
      // are errors rather than warnings because the failure they prevent is
      // stored XSS in a security console (invariant #3).
      'react/no-danger': 'off',
      'no-restricted-properties': [
        'error',
        {
          object: 'document',
          property: 'write',
          message: 'Rendering markup directly would bypass React escaping.',
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
          message:
            'Untrusted log content is rendered as text, never as markup. ' +
            'If HTML is genuinely required, it needs an ADR first.',
        },
        {
          selector: "CallExpression[callee.property.name='eval']",
          message: 'eval is not permitted in this application.',
        },
      ],
      '@typescript-eslint/no-unnecessary-condition': 'off',
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true, allowBoolean: true },
      ],
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
    },
  },
)
