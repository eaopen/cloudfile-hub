const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i

function canonical(path) {
  return path === '/' || (path.startsWith('/') && path.slice(1).split('/').every(
    name => name && name !== '.' && name !== '..' && !/[\\\u0000-\u001f\u007f]/.test(name)
  ))
}

export function readLocation(url, instanceId = 1) {
  const base = '/inst/' + instanceId
  if (url.pathname === base || url.pathname === base + '/') return null
  if (!url.pathname.startsWith(base + '/')) throw new Error('实例地址不匹配')
  const match = /^([^/]+)\/?$/.exec(url.pathname.slice(base.length + 1))
  if (!match || !uuid.test(match[1])) throw new Error('资料库地址无效')
  const root = url.searchParams.get('root') ?? '/'
  const path = url.searchParams.get('path') ?? root
  if (!canonical(root) || !canonical(path) || (root !== '/' && path !== root && !path.startsWith(root + '/'))) {
    throw new Error('目录地址超出入口范围')
  }
  return { id: match[1], root, path }
}

export function driveLink(id, root = '/', path = root, instanceId = 1) {
  const query = new URLSearchParams()
  if (root !== '/') query.set('root', root)
  if (path !== root) query.set('path', path)
  return '/inst/' + instanceId + '/' + id + (query.size ? '?' + query : '')
}

export function childPath(path, name) {
  return (path === '/' ? '' : path) + '/' + name
}
