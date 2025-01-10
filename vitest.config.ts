import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/testSetup.ts'],
    coverage: {
      provider: 'v8',
      reporter: [
        'text',
        'html'
      ]
    }
  }
})
