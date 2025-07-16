import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    test: {
      environment: 'node',
      globals: true,
      setupFiles: ['./server/tests/setup.js'],
      testTimeout: 30000,
      hookTimeout: 30000,
      env: {
        ...env,
        NODE_ENV: 'test',
        DATABASE_URL: env.DATABASE_URL || 'postgresql://postgres:123456@localhost:5432/postgres1',
        JWT_SECRET: 'test-jwt-secret',
        APP_URL: 'http://localhost:3000'
      }
    },
  };
});
