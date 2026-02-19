import type { Config } from "jest";

const config: Config = {
    preset: "ts-jest",
    testEnvironment: "node",
    testMatch: ["**/tests/**/*.test.ts"],
    coverageDirectory: "coverage",
    collectCoverageFrom: ["src/**/*.ts"],
    // Key generation is slow — give each test file a generous timeout
    testTimeout: 30000,
};

export default config;