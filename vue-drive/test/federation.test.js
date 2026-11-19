import test from 'node:test'
import assert from 'node:assert/strict'
import { configuredInstances, routeInstance } from '../src/instances.js'
import { driveLink, readLocation } from '../src/location.js'
import { directory, downloadLink, fileUrl, uploadFile } from '../src/api.js'

const origin = 'https://drive.example'
const repo = 'f12023b8-6893-43d5-baf3-44f865071e03'
const registry = config => configuredInstances(JSON.stringify(config), origin)
const instances = registry([{ id: 1 }, { id: 2 }, { id: 10 }])

test('no config preserves native endpoints, CSRF cookie and file origin', () => {
  const [i] = configuredInstances(undefined, origin, 'https://files.example')
  assert.equal(i.id, 1)
  assert.equal(i.prefix, '')
  assert.equal(i.csrfCookie, 'sfcsrftoken')
  assert.equal(i.fileBase, 'https://files.example/')
  assert.equal(driveLink(repo), '/inst/1/' + repo)
})

test('canonical instance ids only, with no fallback for retired or invalid ids', () => {
  assert.equal(routeInstance('/', instances), null)
  for (const i of instances) {
    const href = driveLink(repo, '/合同', '/合同/# & +%', i.id)
    assert.equal(routeInstance(href, instances), i)
    assert.equal(readLocation(new URL(href, origin), i.id).path, '/合同/# & +%')
  }
  for (const id of ['0', '01', '11', '3', '2extra']) {
    assert.throws(() => routeInstance('/inst/' + id + '/' + repo, instances))
  }
  for (const config of [[], [{ id: 2 }], [{ id: 1 }, { id: 1 }], [{ id: '1' }], [{ id: 1 }, { id: 11 }]]) {
    assert.throws(() => registry(config))
  }
})

test('same UUID and path sign and browse on the selected Hub only', async t => {
  t.mock.method(globalThis, 'fetch', async path => {
    const i = routeInstance(path, instances)
    const url = new URL(path, origin)
    assert.equal(url.searchParams.get('p'), '/相同 #/%')
    if (url.pathname.endsWith('/dir/')) {
      assert.equal(url.pathname, i.prefix + '/api/v2.1/repos/' + repo + '/dir/')
      return Response.json({ dir_id: 'head-' + i.id })
    }
    assert.equal(url.pathname, i.prefix + '/api2/repos/' + repo + '/file/')
    return Response.json(i.fileBase + 'files/ticket')
  })
  for (const instance of instances) {
    const target = { id: repo, instance, path: '/相同 #/%' }
    assert.equal((await directory(target, 0)).dir_id, 'head-' + instance.id)
    assert.equal(await downloadLink(target, target.path), instance.fileBase + 'files/ticket')
  }
})

test('file service scope excludes a peer on the same host or a different host', () => {
  const [one, two] = instances
  assert.throws(() => registry([{ id: 1, fileBase: '/files/' }, { id: 2, fileBase: '/files/nested/' }]))
  for (const ticket of [two.fileBase + 'upload-api/ticket', 'https://other.example/seafhttp/files/ticket']) {
    assert.throws(() => fileUrl(ticket, one), /文件服务地址/)
  }
})

test('upload signs on the target Hub with its own CSRF cookie and sends bytes to its file service', async t => {
  const [one, two] = instances
  const target = { instance: two, id: repo, path: '/合同' }
  const transfer = []
  const saved = { document: globalThis.document, xhr: globalThis.XMLHttpRequest }
  globalThis.document = { cookie: 'cfi1_csrf=one; cfi2_csrf=two' }
  globalThis.XMLHttpRequest = class {
    upload = {}
    open(method, url) { transfer.push([method, url]) }
    send(form) {
      transfer.push([form.get('parent_dir'), form.get('file').name])
      this.status = 200
      this.onload()
      this.onloadend()
    }
  }
  t.after(() => {
    if (saved.document === undefined) delete globalThis.document
    else globalThis.document = saved.document
    if (saved.xhr === undefined) delete globalThis.XMLHttpRequest
    else globalThis.XMLHttpRequest = saved.xhr
  })
  let ticket = one.fileBase + 'upload-api/ticket'
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, two.prefix + '/api/v2.1/cloudfile/repos/' + repo + '/upload-session/')
    assert.equal(init.headers['X-CSRFToken'], 'two')
    assert.deepEqual(JSON.parse(init.body), { parent_dir: target.path })
    return Response.json({ parent_dir: target.path, upload_url: ticket })
  })
  const file = new File(['instance two'], 'same.txt')
  const send = () => uploadFile(target, file, new AbortController().signal, () => {})
  await assert.rejects(send(), /文件服务地址/)
  assert.deepEqual(transfer, [])
  ticket = two.fileBase + 'upload-api/ticket'
  await send()
  assert.deepEqual(transfer, [['POST', ticket], [target.path, file.name]])
})
