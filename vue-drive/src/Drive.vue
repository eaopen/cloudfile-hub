<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { libraries, directory, downloadLink, uploadFile } from './api.js'
import { readLocation, driveLink, childPath } from './location.js'

const entries = ref([])
const target = ref(null)
const page = ref(null)
const offsets = ref([0])
const loading = ref(false)
const error = ref('')
const signedIn = ref(false)
const sessionRequired = ref(false)
const transfer = ref(null)
const feedback = ref('')
const input = ref(null)
const order = ref('native')
let controller

const login = () => location.assign('/oauth/login/?next=' + encodeURIComponent(location.pathname + location.search))
const label = computed(() => entries.value.find(item =>
  item.id === target.value?.id && item.root === target.value?.root)?.name || target.value?.id)
const rows = computed(() => {
  const list = page.value?.dirent_list || []
  return order.value === 'name' ? [...list].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN', { numeric: true })) : list
})
const crumbs = computed(() => {
  if (!target.value) return []
  const { root, path } = target.value
  const result = [{ name: label.value, path: root }]
  for (const name of path.slice(root.length).split('/').filter(Boolean)) {
    result.push({ name, path: childPath(result.at(-1).path, name) })
  }
  return result
})

function startRead() {
  controller?.abort()
  controller = new AbortController()
  loading.value = true
  transfer.value = null
  error.value = ''
  feedback.value = ''
  return controller.signal
}

function failed(failure, signal) {
  if (signal.aborted) return
  error.value = failure.message
  if (failure.status === 401) sessionRequired.value = true
}

async function openLocation() {
  const signal = startRead()
  sessionRequired.value = false
  page.value = null
  offsets.value = [0]
  target.value = null
  entries.value = []
  signedIn.value = false
  try {
    target.value = readLocation(new URL(location.href))
    const discovered = await libraries(signal)
    if (signal.aborted) return
    entries.value = discovered
    signedIn.value = true
    if (target.value) {
      const first = await directory(target.value, 0, null, signal)
      if (!signal.aborted) page.value = first
    }
  } catch (failure) {
    failed(failure, signal)
  } finally {
    if (!signal.aborted) loading.value = false
  }
}

function follow(event) {
  if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return
  event.preventDefault()
  history.pushState(null, '', event.currentTarget.href)
  void openLocation()
}

async function turn(next) {
  if (loading.value || !page.value || transfer.value !== null) return
  const nextOffsets = next ? [...offsets.value, page.value.next_start] : offsets.value.slice(0, -1)
  if (!nextOffsets.length || nextOffsets.at(-1) == null) return
  const signal = startRead()
  try {
    const result = await directory(target.value, nextOffsets.at(-1), page.value.dir_id, signal)
    if (!signal.aborted) {
      page.value = result
      offsets.value = nextOffsets
    }
  } catch (failure) {
    if (signal.aborted) return
    if (failure.status === 409) {
      await openLocation()
      return
    }
    if ([401, 403, 404].includes(failure.status)) page.value = null
    failed(failure, signal)
  } finally {
    if (!signal.aborted) loading.value = false
  }
}

async function download(name) {
  const signal = controller.signal
  error.value = ''
  try {
    const link = document.createElement('a')
    link.href = await downloadLink(target.value.id, childPath(target.value.path, name), signal)
    if (signal.aborted) return
    link.download = name
    link.referrerPolicy = 'no-referrer'
    link.click()
  } catch (failure) { failed(failure, signal) }
}

async function upload(event) {
  const file = event.target.files[0]
  event.target.value = ''
  if (!file || transfer.value !== null || loading.value) return
  const signal = controller.signal
  transfer.value = 0
  feedback.value = ''
  error.value = ''
  try {
    await uploadFile(target.value, file, signal, amount => { if (!signal.aborted) transfer.value = amount })
    if (signal.aborted) return
    const href = location.href
    await openLocation()
    if (location.href === href && signedIn.value) feedback.value = '已上传 ' + file.name
  } catch (failure) { failed(failure, signal) }
  finally { if (!signal.aborted) transfer.value = null }
}

onMounted(() => { window.addEventListener('popstate', openLocation); void openLocation() })
onBeforeUnmount(() => { window.removeEventListener('popstate', openLocation); controller?.abort() })
</script>

<template>
  <header><div class="bar"><a href="/inst/1/" class="brand" @click="follow">CloudFile</a>
    <a v-if="signedIn" href="/accounts/logout/">退出登录</a></div></header>
  <main>
    <template v-if="sessionRequired">
      <h1>登录网盘</h1><button class="primary" @click="login">使用单点登录</button>
    </template>
    <template v-else>
      <nav v-if="target" aria-label="目录路径"><a href="/inst/1/" @click="follow">资料库</a>
        <template v-for="crumb in crumbs" :key="crumb.path"><span>/</span>
          <a :href="driveLink(target.id, target.root, crumb.path)" @click="follow">{{ crumb.name }}</a>
        </template></nav>
      <div class="heading"><h1>{{ target ? crumbs.at(-1)?.name : '资料库' }}</h1>
        <div class="actions">
          <button :disabled="loading || transfer !== null" @click="openLocation">刷新</button>
          <template v-if="page?.user_perm === 'rw'">
            <input ref="input" type="file" hidden @change="upload">
            <button class="primary" :disabled="loading || transfer !== null" @click="input.click()">上传文件</button>
          </template>
        </div>
      </div>
      <p v-if="error" role="alert">{{ error }}</p>
      <p v-if="feedback" role="status">{{ feedback }}</p>
      <p v-if="transfer !== null" role="status">正在上传 · {{ transfer }}%</p>
      <p v-if="loading" role="status">正在读取…</p>
      <ul v-if="!target && entries.length" class="libraries">
        <li v-for="item in entries" :key="driveLink(item.id, item.root)">
          <a :href="driveLink(item.id, item.root)" @click="follow">{{ item.name }}</a>
          <small>{{ item.root === '/' ? '资料库' : '共享目录' }}</small>
        </li>
      </ul>
      <p v-else-if="!target && !loading && !error">暂无可访问的资料库或共享目录</p>
      <template v-if="target && page">
        <label>本页排序 <select v-model="order"><option value="native">目录顺序</option><option value="name">文件名</option></select></label>
        <table><thead><tr><th>名称</th><th>大小</th><th>操作</th></tr></thead><tbody>
          <tr v-for="item in rows" :key="item.name"><td>
            <a v-if="item.type === 'dir'" :href="driveLink(target.id, target.root, childPath(target.path, item.name))" @click="follow">{{ item.name }}/</a>
            <span v-else>{{ item.name }}</span>
          </td><td>{{ item.type === 'file' ? item.size.toLocaleString() + ' B' : '—' }}</td>
          <td><button v-if="item.type === 'file'" @click="download(item.name)">下载</button></td></tr>
        </tbody></table>
        <p v-if="!rows.length">本页没有可见条目</p>
        <footer v-if="page.has_more || offsets.length > 1">
          <button :disabled="loading || transfer !== null || offsets.length === 1" @click="turn(false)">上一页</button>
          <span>第 {{ offsets.length }} 页</span>
          <button :disabled="loading || transfer !== null || !page.has_more" @click="turn(true)">下一页</button>
        </footer>
      </template>
    </template>
  </main>
</template>
