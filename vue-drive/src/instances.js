const validId = /^(?:[1-9]|10)$/

export function configuredInstances(raw, origin, legacyFileOrigin) {
  if (raw == null || raw === '') {
    return [{ id: 1, label: '', prefix: '', csrfCookie: 'sfcsrftoken',
      fileBase: new URL(legacyFileOrigin || origin).origin + '/' }]
  }
  const instances = []
  const config = JSON.parse(raw)
  if (!Array.isArray(config)) throw new Error('实例配置必须是数组')
  for (const entry of config) {
    if (!entry || !Number.isInteger(entry.id) || !validId.test(entry.id) || instances.some(i => i.id === entry.id)) {
      throw new Error('实例编号必须是唯一的 1–10 整数')
    }
    const prefix = '/inst/' + entry.id
    const url = new URL(entry.fileBase || prefix + '/seafhttp/', origin)
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new Error('文件服务配置无效')
    }
    const fileBase = url.href.replace(/\/?$/, '/')
    if (instances.some(i => i.fileBase.startsWith(fileBase) || fileBase.startsWith(i.fileBase))) {
      throw new Error('各实例的文件服务地址范围必须独立')
    }
    instances.push({ id: entry.id, label: entry.label || '实例 ' + entry.id,
      prefix, fileBase, csrfCookie: 'cfi' + entry.id + '_csrf' })
  }
  if (!instances.some(i => i.id === 1)) throw new Error('缺少默认实例 1')
  return instances
}

export function routeInstance(path, instances) {
  if (path === '/') return null
  const segment = /^\/inst\/([^/]+)(?:\/|$)/.exec(path)?.[1]
  const instance = validId.test(segment) && instances.find(i => i.id === Number(segment))
  if (!instance) throw new Error('网盘实例地址无效或未配置')
  return instance
}
