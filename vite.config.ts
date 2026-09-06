import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.ico', 'shield.svg'],
      manifest: {
        name: '安全密码恢复哈希提取器 - 淘宝@大希软件服务',
        short_name: '哈希提取器',
        description: '纯浏览器本地离线解析，零文件上传，安全提取 PDF、Office、ZIP 密码恢复哈希。',
        theme_color: '#0f172a',
        background_color: '#020617',
        display: 'standalone',
        icons: [
          {
            src: 'shield.svg',
            sizes: '192x192 512x512',
            type: 'image/svg+xml',
          },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,wasm}'],
      },
    }),
  ],
})
