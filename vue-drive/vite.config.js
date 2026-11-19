import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const hub = process.env.CLOUDFILE_DEV_UPSTREAM
const proxy = hub && Object.fromEntries(
  ['/api2/', '/api/v2.1/', '/oauth/', '/accounts/', '/seafhttp/', '/media/', '/static/']
    .map(prefix => [prefix, hub])
)

export default defineConfig({
  plugins: [vue()],
  base: '/inst/1/',
  server: { proxy },
})
