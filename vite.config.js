// vite.config.js
import { resolve } from 'path'
import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    sourcemap: true,
    lib: {
      // Could also be a dictionary or array of multiple entry points
      entry: resolve(__dirname, 'index.js'),
      name: 'SecureWithJWT',
      // the proper extensions will be added
      fileName: 'secure-with-jwt',
      formats: ['cjs', 'es']
    }
  },
  test: {
    setupFiles: ['./test/testSetup.js']
  }
})
