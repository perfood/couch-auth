import { defineConfig, globalIgnores } from "eslint/config";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default defineConfig([
    ...compat.extends("plugin:@typescript-eslint/recommended", "prettier"),
    { ignores: ['lib/*', 'coverage/*', '**/*.d.ts', 'src/public/', 'src/types/'] },
    {
        languageOptions: {
            parser: tsParser,
            ecmaVersion: 2020,
            sourceType: "module",
        },

        rules: {
            semi: ["error", "always"],

            quotes: ["error", "single", {
                avoidEscape: true,
            }],

            "no-var": "warn",
            "prefer-const": "warn",
            "@typescript-eslint/explicit-function-return-type": "off",
            "@typescript-eslint/explicit-module-boundary-types": "off",
            "@typescript-eslint/camelcase": "off",
            "@typescript-eslint/no-restricted-types": "error",
            "@typescript-eslint/ban-ts-comment": "off",
            "@typescript-eslint/no-empty-function": "off",
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-unused-expressions": "warn",
            "@typescript-eslint/no-require-imports": "warn",
            "@typescript-eslint/no-unsafe-function-type": "warn",

            "@typescript-eslint/no-inferrable-types": ["warn", {
                ignoreParameters: true,
            }],

            "@typescript-eslint/no-unused-vars": ["warn", {
                args: "none",
            }],

            "@typescript-eslint/no-use-before-define": "off",
            "@typescript-eslint/no-var-requires": "off",
        },
    },
]);