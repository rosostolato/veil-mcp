import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Security tests inspect process-wide channels; keep them off one another's toes.
    fileParallelism: true,
  },
});
