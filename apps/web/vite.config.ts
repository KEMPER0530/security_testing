import { defineConfig } from "vite";
export default defineConfig({
  envDir: "../..",
  oxc: { jsx: { runtime: "automatic" } },
  build: {
    rollupOptions: {
      onwarn(warning, warn) {
        if (warning.code !== "MODULE_LEVEL_DIRECTIVE") warn(warning);
      },
    },
  },
});
