import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";

// Flat config: `next lint` was removed in Next 16, so eslint runs directly and
// needs the config at the root rather than an `eslintConfig` key in package.json.
// eslint-config-next ships flat-config arrays, so they spread in as-is.
const config = [
  {
    ignores: [".next/**", "node_modules/**", "next-env.d.ts", "tsconfig.tsbuildinfo"],
  },
  ...coreWebVitals,
  ...typescript,
];

export default config;
