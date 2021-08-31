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

describe('crypto-pouch', function () {
  beforeEach(async function () {
    this.db = new PouchDB(NAME, { db: memdown })
    await this.db.crypto(PASSWORD)
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

  it('should not encrypt documents after crypto is removed', async function () {
    const [doc1, doc2] = DOCS.slice(0, 2)
    await this.db.put(doc1)
    this.db.removeCrypto()
    await this.db.put(doc2)
    const encrypted = await this.db.get(doc1._id)
    assert.notEqual(encrypted.hello, doc1.hello)
    const decrypted = await this.db.get(doc2._id)
    assert.equal(decrypted.hello, doc2.hello)
  })

  it('should fail when using a bad password', async function () {
    await this.db.put({ _id: 'a', hello: 'world' })
    this.db.removeCrypto()
    await this.db.crypto(BAD_PASS)
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
    await this.db.crypto(PASSWORD, { ignore: '_attachments' })
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
    await this.db.crypto({ password: PASSWORD })
    const doc = DOCS[0]
    await this.db.put(doc)
    const { hello } = await this.db.get(doc._id)
    assert.equal(hello, 'world')
  })

  it('should fail to init with http adapter', async function () {
    const db = new PouchDB('http://localhost:5984')
    assert.rejects(
      async () => { await db.crypto(PASSWORD) },
      new Error('crypto-pouch does not work with pouchdb\'s http adapter. Use a local adapter instead.')
    )
  })

  it('should preserve ignored fields on read', async function () {
    let doc = DOCS[0]
    assert(!('_rev' in doc))
    await this.db.put(doc)
    doc = await this.db.get(doc._id)
    assert('_rev' in doc)
  })

  describe('replication', async function () {
    beforeEach(async function () {
      this.db2 = new PouchDB(NAME + '2')
    })

    afterEach(async function () {
      await this.db2.destroy()
    })

    it('should replicate ok', async function () {
      await this.db.bulkDocs(DOCS)
      await this.db.replicate.to(this.db2)
      const result = await this.db2.allDocs()
      assert.equal(result.rows.length, DOCS.length)
    })
  })

  describe('concurrency', function () {
    beforeEach(async function () {
      this.db1 = new PouchDB(NAME)
      this.db2 = new PouchDB(NAME)
    })

    afterEach(async function () {
      await this.db1.destroy() // also destroys db2 THANKS
    })

    it('should handle concurrent crypt instances ok', async function () {
      this.timeout(10 * 1000)
      await Promise.all([
        this.db1.crypto(PASSWORD),
        this.db2.crypto(PASSWORD)
      ])
      await this.db1.put(DOCS[0])
      const doc = await this.db2.get(DOCS[0]._id)
      assert.equal(DOCS[0].hello, doc.hello)
    })
  })
})
