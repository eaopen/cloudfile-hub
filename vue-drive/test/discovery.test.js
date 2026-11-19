import assert from 'node:assert/strict'
import test from 'node:test'
import { libraries } from '../src/api.js'

function mockHub(t, repos, shares) {
  return t.mock.method(globalThis, 'fetch', async path => {
    if (path === '/api2/repos/') return repos
    assert.equal(path, '/api/v2.1/cloudfile/authorization/v1/shared-directories/')
    return shares
  })
}

test('duplicate native grants keep one library and each distinct shared root', async t => {
  const repo = { id: 'r', name: 'Library' }
  const share = { repo_id: 'r', path: '/team' }
  mockHub(t, Response.json([repo, repo]), Response.json({ data: [
    { repo_id: 'r', path: '/' }, share, share, { repo_id: 's', path: '/team' },
  ] }))
  assert.deepEqual(await libraries(), [
    { id: 'r', name: 'Library', root: '/' },
    { id: 'r', name: '/team', root: '/team' },
    { id: 's', name: '/team', root: '/team' },
  ])
})

test('an anonymous library request prompts login without querying shares', async t => {
  const fetch = mockHub(t, new Response(null, { status: 403 }))
  await assert.rejects(libraries(), { status: 401 })
  assert.equal(fetch.mock.callCount(), 1)
})

test('shared directory denial for an authenticated user stays a permission error', async t => {
  mockHub(t, Response.json([]), new Response(null, { status: 403 }))
  await assert.rejects(libraries(), { status: 403 })
})
