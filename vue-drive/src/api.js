export class HubError extends Error {
  constructor(status) {
    super(({401: '登录状态已过期', 403: '没有此操作的权限', 404: '目录或文件已不存在',
      409: '目录内容已变化，请刷新后继续'})[status] || '网盘请求失败，请重试')
    this.status = status
  }
}

async function json(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', redirect: 'error', ...options })
  if (!response.ok) throw new HubError(response.status)
  return response.json()
}

export async function libraries(signal) {
  const [repos, shares] = await Promise.all([
    json('/api2/repos/', { signal }),
    json('/api/v2.1/cloudfile/authorization/v1/shared-directories/', { signal }),
  ])
  return [
    ...repos.map(repo => ({ id: repo.id, name: repo.name, root: '/' })),
    ...shares.data.map(entry => ({ id: entry.repo_id, name: entry.path, root: entry.path })),
  ]
}

export function directory({ id, path }, start, version, signal) {
  const params = new URLSearchParams({ p: path, start, limit: 100 })
  if (version) params.set('if_dir_id', version)
  return json('/api/v2.1/repos/' + id + '/dir/?' + params, { signal })
}

function fileUrl(ticket) {
  if (typeof ticket !== 'string' || !ticket.trim()) throw new Error('缺少文件服务地址')
  const url = new URL(ticket, location.origin)
  const allowed = new URL(import.meta.env.VITE_FILE_ORIGIN || location.origin)
  if (!['https:', 'http:'].includes(url.protocol) || url.origin !== allowed.origin || url.username || url.password) {
    throw new Error('文件服务地址与配置不一致')
  }
  return url.href
}

export async function downloadLink(id, path, signal) {
  const params = new URLSearchParams({ p: path })
  return fileUrl(await json('/api2/repos/' + id + '/file/?' + params, { signal }))
}

export async function uploadFile({ id, path }, file, signal, progress) {
  const csrf = document.cookie.split('; ').find(cookie => cookie.startsWith('sfcsrftoken='))?.slice('sfcsrftoken='.length)
  const session = await json('/api/v2.1/cloudfile/repos/' + id + '/upload-session/', {
    signal, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf || '' },
    body: JSON.stringify({ parent_dir: path }),
  })
  if (session.parent_dir !== path) throw new Error('上传目标已变化')
  const url = fileUrl(session.upload_url)
  const data = new FormData()
  data.append('parent_dir', path)
  data.append('file', file)
  await new Promise((resolve, reject) => {
    signal.throwIfAborted()
    const request = new XMLHttpRequest()
    const abort = () => request.abort()
    request.open('POST', url)
    request.upload.onprogress = event => {
      if (event.lengthComputable) progress(Math.floor(100 * event.loaded / event.total))
    }
    request.onload = () => request.status >= 200 && request.status < 300 ? resolve() : reject(new HubError(request.status))
    request.onerror = () => reject(new Error('上传连接中断，请刷新目录确认文件状态'))
    request.onabort = () => reject(new DOMException('Upload cancelled', 'AbortError'))
    request.onloadend = () => signal.removeEventListener('abort', abort)
    signal.addEventListener('abort', abort, { once: true })
    request.send(data)
  })
}
