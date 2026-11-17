// Lint rules for the extension's TypeScript, with type information.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "out", "node_modules", "eslint.config.mjs"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    // Plain JavaScript scripts have no types to check.
    files: ["**/*.mjs"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: { console: "readonly" } },
  },
);
