import { createApp } from 'vue'
import Drive from './Drive.vue'
import './style.css'
import { configuredInstances } from './instances.js'

try {
  const instances = configuredInstances(import.meta.env.VITE_CLOUDFILE_INSTANCES, location.origin, import.meta.env.VITE_FILE_ORIGIN)
  createApp(Drive, { instances }).mount('#app')
} catch (error) {
  document.getElementById('app').textContent = '网盘配置错误：' + error.message
}
