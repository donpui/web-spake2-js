import js from '@eslint/js'
import { FlatCompat } from '@eslint/eslintrc'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const compat = new FlatCompat({ baseDirectory: __dirname })

export default [
  { ignores: ['tests/browser/dist/**'] },
  js.configs.recommended,
  ...compat.extends(
    'plugin:import/recommended',
    'plugin:n/recommended',
    'plugin:promise/recommended'
  ),
  {
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    rules: {
      'no-console': 'off',
      'n/no-unsupported-features/node-builtins': 'off'
    }
  }
]