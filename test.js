/* global describe it beforeEach afterEach emit */

const assert = require('assert').strict
const memdown = require('memdown')
const PouchDB = require('pouchdb')
PouchDB.plugin(require('.'))

const PASSWORD = 'hello world'
const BAD_PASS = 'goodbye sol'
const NAME = 'crypto-pouch-testing'
const DOCS = [
  { _id: 'a', hello: 'world' },
  { _id: 'b', hello: 'sol' },
  { _id: 'c', hello: 'galaxy' }
]
const ATTACHMENTS = {
  'att.txt': {
    content_type: 'text/plain',
    data: 'TGVnZW5kYXJ5IGhlYXJ0cywgdGVhciB1cyBhbGwgYXBhcnQKTWFrZSBvdXIgZW1vdGlvbnMgYmxlZWQsIGNyeWluZyBvdXQgaW4gbmVlZA=='
  }
}

function getPouchDB () {
  if (process.env.USE_COUCH && process.env.COUCH_URL) {
    return new PouchDB(`${process.env.COUCH_URL}/${NAME}`)
  } else {
    return new PouchDB(NAME, { db: memdown })
  }
}

describe('crypto-pouch', function () {
  beforeEach(function () {
    this.db = getPouchDB()
    this.db.crypto(PASSWORD)
  })

  afterEach(async function () {
    await this.db.destroy()
  })

  it('should encrypt documents', async function () {
    const doc = DOCS[0]
    await this.db.put(doc)
    const decrypted = await this.db.get(doc._id)
    assert.equal(decrypted.hello, doc.hello)
    // now let's ensure that doc is encrypted at rest
    this.db.removeCrypto()
    const encrypted = await this.db.get(doc._id)
    assert.notEqual(encrypted.hello, doc.hello)
  })

  it('should fail when using a bad password', async function () {
    await this.db.put({ _id: 'a', hello: 'world' })
    this.db.removeCrypto()
    this.db.crypto(BAD_PASS)
    try {
      await this.db.get('a')
      throw new Error('read succeeded but should have failed')
    } catch (error) {
      assert.equal(error.message, 'Could not decrypt!')
    }
  })

  it('should preserve primary index sorting', async function () {
    for (const doc of DOCS) { await this.db.put(doc) }
    const result = await this.db.allDocs()
    for (let i = 0; i < result.rows.length - 1; i++) {
      const row = result.rows[i]
      const next = result.rows[i + 1]
      assert(row.key < next.key)
    }
  })

  it('should preserve secondary index sorting', async function () {
    for (const doc of DOCS) { await this.db.put(doc) }
    await this.db.put({
      _id: '_design/test',
      views: {
        test: {
          map: function (doc) { emit(doc.hello) }.toString()
        }
      }
    })
    const result = await this.db.query('test')
    const EXPECTED = DOCS.map(({ hello }) => { return hello })
    for (let i = 0; i < result.rows.length - 1; i++) {
      const row = result.rows[i]
      const next = result.rows[i + 1]
      assert(row.key < next.key)
      // ensure that keys are not encrypted
      assert(EXPECTED.includes(row.key))
      assert(EXPECTED.includes(next.key))
    }
  })

  it('should error on attachments', async function () {
    const doc = { ...DOCS[0], _attachments: ATTACHMENTS }
    try {
      await this.db.put(doc)
      throw new Error('write should not have succeeded')
    } catch (error) {
      assert.equal(error.message, 'Attachments cannot be encrypted. Use {ignore: "_attachments"} option')
    }
  })

  it('should ignore attachments when so instructed', async function () {
    this.db.removeCrypto()
    this.db.crypto(PASSWORD, { ignore: '_attachments' })
    const doc = { ...DOCS[0], _attachments: ATTACHMENTS }
    await this.db.put(doc)
  })

  it('should handle _deleted:true ok', async function () {
    const doc = DOCS[0]
    const { rev } = await this.db.put(doc)
    const deleted = { _id: doc._id, _rev: rev, _deleted: true }
    await this.db.put(deleted)
    try {
      await this.db.get(doc._id)
      throw new Error('read should not have succeeded')
    } catch (error) {
      assert.equal(error.reason, 'deleted')
    }
  })

  it('should accept crypto params as an object', async function () {
    this.db.removeCrypto()
    this.db.crypto({ password: PASSWORD })
    await this.db.put(DOCS[0])
  })
})
