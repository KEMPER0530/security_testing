import tseslint from "typescript-eslint";
export default tseslint.config(
  { ignores: ["**/schema.d.ts", "**/dist/**"] },
  ...tseslint.configs.recommended,
  {
    files: [
      "apps/web/src/domain/**/*.{ts,tsx}",
      "apps/web/src/application/**/*.{ts,tsx}",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            "react",
            "react-dom",
            "@tanstack/*",
            "@security-testing/api-client",
            "**/infrastructure/*",
            "**/presentation/*",
          ],
        },
      ],
    },
  },
  { rules: { "@typescript-eslint/no-explicit-any": "off" } },
);
