// ESLint flat config: JavaScript recommended rules plus typescript-eslint.
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "coverage/", "node_modules/"] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // Plain JavaScript test helpers run directly by Node.
    files: ["**/*.mjs", "**/*.js"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly", setTimeout: "readonly" },
    },
  },
);
