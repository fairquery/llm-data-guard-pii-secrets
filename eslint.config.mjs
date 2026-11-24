import prettier from 'eslint-config-prettier';

import apify from '@apify/eslint-config/ts.js';
import globals from 'globals';
import tsEslint from 'typescript-eslint';

// eslint-disable-next-line import-x/no-default-export
export default [
    { ignores: ['**/dist', '**/test', 'eslint.config.mjs'] },
    ...apify,
    prettier,
    {
        languageOptions: {
            globals: {
                ...globals.node,
                ...globals.jest,
            },
        },
        settings: {
            // Do not parse dependency sources. unpdf's bundled pdfjs.mjs overflows
            // the TypeScript parser during import analysis.
            'import-x/ignore': ['node_modules'],
        },
        rules: {
            'no-console': 0,
        },
    },
    {
        // Type-aware linting follows the nearest tsconfig: root src uses
        // tsconfig.json, mcp/src uses mcp/tsconfig.json. JS outside those
        // projects keeps the JS parser from the base config.
        files: ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts'],
        languageOptions: {
            parser: tsEslint.parser,
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
        plugins: {
            '@typescript-eslint': tsEslint.plugin,
        },
    },
];
