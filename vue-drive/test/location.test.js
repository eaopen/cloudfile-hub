import test from 'node:test'
import assert from 'node:assert/strict'
import { driveLink, readLocation, childPath } from '../src/location.js'

const repo = 'f12023b8-6893-43d5-baf3-44f865071e03'
const read = path => readLocation(new URL(path, 'https://drive.example'))

test('instance one has a short selector and a directly bookmarkable repository', () => {
  for (const path of ['/inst/1', '/inst/1/']) assert.equal(read(path), null)
  assert.equal(driveLink(repo), '/inst/1/' + repo)
  assert.deepEqual(read(driveLink(repo)), { id: repo, root: '/', path: '/' })
})

test('shared root and nested names survive query serialization', () => {
  const root = '/合同 #1'
  const path = childPath(root, '补充 & 附件+%')
  assert.deepEqual(read(driveLink(repo, root, path)), { id: repo, root, path })
})

test('unsupported instances, repository identifiers and ambiguous directory paths are rejected', () => {
  for (const path of ['/inst/2/' + repo, '/inst/1/bad', driveLink(repo, '/team', '/team2'),
    driveLink(repo, '/team', '/team/../other'), driveLink(repo, '/', '/folder//name')]) {
    assert.throws(() => read(path))
  }
})
