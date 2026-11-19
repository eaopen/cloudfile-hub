<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { libraries, directory, downloadLink, uploadFile } from './api.js'
import { readLocation, driveLink, childPath } from './location.js'
import { routeInstance } from './instances.js'

const { instances } = defineProps({ instances: { type: Array, required: true } })
const overview = instances.length > 1 ? '/' : '/inst/1/'
const active = ref(null)
const groups = ref([])
const pendingLogout = ref(null)
const logoutKey = 'cloudfile.vue-drive.pending-logout'
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

function login(instance) {
  location.assign(instance.prefix + '/oauth/login/?next=' + encodeURIComponent(location.pathname + location.search))
}
const libraryLink = (item, path = item.root) => driveLink(item.id, item.root, path, item.instance.id)
const connected = computed(() => active.value || groups.value.find(group => group.items)?.instance)
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
  active.value = null
  groups.value = []
  try {
    if (instances.length > 1) {
      const pending = localStorage.getItem(logoutKey)
      pendingLogout.value = instances.find(i => String(i.id) === pending)
      if (pendingLogout.value) {
        const states = await Promise.all(instances.map(i => isSignedOut(i, signal)))
        if (signal.aborted || !states.every(Boolean)) return
        localStorage.removeItem(logoutKey)
        pendingLogout.value = null
      }
    }
    const url = new URL(location.href)
    const selected = routeInstance(url.pathname, instances)
    if (!selected && instances.length > 1) {
      groups.value = instances.map(instance => ({ instance, items: null, error: null }))
      await Promise.all(groups.value.map(async group => {
        try {
          const bounded = AbortSignal.any([signal, AbortSignal.timeout(15000)])
          const items = await libraries(bounded, group.instance.prefix)
          if (!signal.aborted) group.items = items.map(item => ({ ...item, instance: group.instance }))
        } catch (failure) {
          if (!signal.aborted) group.error = failure.status ? failure : new Error('实例暂不可用，请稍后刷新')
        }
      }))
      return
    }
    const instance = selected || instances.find(i => i.id === 1)
    active.value = instance
    const resource = selected && readLocation(url, instance.id)
    target.value = resource ? { ...resource, instance } : null
    const discovered = await libraries(signal, instance.prefix)
    if (signal.aborted) return
    entries.value = discovered.map(item => ({ ...item, instance }))
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

async function isSignedOut(instance, signal) {
  const probe = await fetch(instance.prefix + '/api2/repos/', {
    redirect: 'error', cache: 'no-store', signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
  })
  return [401, 403].includes(probe.status)
}

async function logout(event) {
  if (instances.length === 1) return
  event.preventDefault()
  const last = pendingLogout.value || connected.value
  localStorage.setItem(logoutKey, String(last.id))
  pendingLogout.value = last
  const signal = startRead()
  groups.value = []
  entries.value = []
  page.value = null
  signedIn.value = false
  try {
    await Promise.all(instances.filter(i => i.id !== last.id).map(async i => {
      await fetch(i.prefix + '/accounts/logout/', { redirect: 'manual', signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) })
      if (!await isSignedOut(i, signal)) throw new Error(i.label + '退出状态未确认')
    }))
    if (!signal.aborted) location.assign(last.prefix + '/accounts/logout/')
  } catch (failure) {
    if (!signal.aborted) {
      error.value = '部分实例退出状态未确认，请刷新后重试'
      loading.value = false
    }
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
    link.href = await downloadLink(target.value, childPath(target.value.path, name), signal)
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

function onLogoutChange(event) { if (event.key === logoutKey) void openLocation() }
function restore(event) { if (event.persisted) void openLocation() }
onMounted(() => { window.addEventListener('storage', onLogoutChange); window.addEventListener('pageshow', restore); window.addEventListener('popstate', openLocation); void openLocation() })
onBeforeUnmount(() => { window.removeEventListener('storage', onLogoutChange); window.removeEventListener('pageshow', restore); window.removeEventListener('popstate', openLocation); controller?.abort() })
</script>

<template>
  <header><div class="bar"><a :href="overview" class="brand" @click="follow">CloudFile</a>
    <a v-if="!pendingLogout && connected && (signedIn || !active)" :href="connected.prefix + '/accounts/logout/'" @click="logout">退出登录</a></div></header>
  <main>
    <template v-if="pendingLogout">
      <h1>正在退出网盘</h1>
      <p role="status">{{ error || '请确认所有实例都已退出。' }}</p>
      <button :disabled="loading" @click="logout">继续退出</button>
    </template>
    <template v-else-if="sessionRequired">
      <h1>登录网盘</h1><button class="primary" @click="login(active)">使用单点登录</button>
    </template>
    <template v-else>
      <nav v-if="target" aria-label="目录路径"><a :href="'/inst/' + active.id + '/'" @click="follow">资料库</a>
        <template v-for="crumb in crumbs" :key="crumb.path"><span>/</span>
          <a :href="libraryLink(target, crumb.path)" @click="follow">{{ crumb.name }}</a>
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
      <section v-for="group in groups" :key="group.instance.id">
        <h2><a :href="'/inst/' + group.instance.id + '/'" @click="follow">{{ group.instance.label }}</a></h2>
        <button v-if="group.error?.status === 401" @click="login(group.instance)">连接{{ group.instance.label }}</button>
        <p v-else-if="group.error" role="alert">{{ group.error.message }}</p>
        <p v-else-if="!group.items">正在读取…</p>
        <p v-else-if="!group.items.length">暂无可访问的资料库或共享目录</p>
        <ul v-else class="libraries"><li v-for="item in group.items" :key="libraryLink(item)">
          <a :href="libraryLink(item)" @click="follow">{{ item.name }}</a>
          <small>{{ item.root === '/' ? '资料库' : '共享目录' }}</small>
        </li></ul>
      </section>
      <ul v-if="active && !target && entries.length" class="libraries">
        <li v-for="item in entries" :key="libraryLink(item)">
          <a :href="libraryLink(item)" @click="follow">{{ item.name }}</a>
          <small>{{ item.root === '/' ? '资料库' : '共享目录' }}</small>
        </li>
      </ul>
      <p v-else-if="active && !target && !loading && !error">暂无可访问的资料库或共享目录</p>
      <template v-if="target && page">
        <label>本页排序 <select v-model="order"><option value="native">目录顺序</option><option value="name">文件名</option></select></label>
        <table><thead><tr><th>名称</th><th>大小</th><th>操作</th></tr></thead><tbody>
          <tr v-for="item in rows" :key="item.name"><td>
            <a v-if="item.type === 'dir'" :href="libraryLink(target, childPath(target.path, item.name))" @click="follow">{{ item.name }}/</a>
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
