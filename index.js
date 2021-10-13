const Crypt = require('garbados-crypt')
const { transform } = require('transform-pouch')

const LOCAL_ID = '_local/crypto'
const IGNORE = ['_id', '_rev', '_deleted', '_conflicts']

const NO_COUCH = 'crypto-pouch does not work with pouchdb\'s http adapter. Use a local adapter instead.'

module.exports = {
  transform,
  crypto: async function (password, options = {}) {
    if (this.adapter === 'http') {
      throw new Error(NO_COUCH)
    }
    if (typeof password === 'object') {
      // handle `db.crypto({ password, ...options })`
      options = password
      password = password.password
      delete options.password
    }
    // setup ignore list
    this._ignore = IGNORE.concat(options.ignore || [])
    // setup crypto helper
    this._crypt = new Crypt(password, options.salt ? options.salt : null, options)
    // instrument document transforms
    this.transform({
      incoming: async (doc) => {
        // if no crypt, ex: after .removeCrypto(), just return the doc
        if (!this._crypt) { return doc }
        if (doc._attachments && !this._ignore.includes('_attachments')) {
          throw new Error('Attachments cannot be encrypted. Use {ignore: "_attachments"} option')
        }
        const encrypted = {}
        for (const key of this._ignore) {
          // attach ignored fields to encrypted doc
          if (key in doc) encrypted[key] = doc[key]
        }
        encrypted.payload = await this._crypt.encrypt(JSON.stringify(doc))
        return encrypted
      },
      outgoing: async (doc) => {
        // if no crypt, ex: after .removeCrypto(), just return the doc
        if (!this._crypt) { return doc }
        const decryptedString = await this._crypt.decrypt(doc.payload)
        const decrypted = JSON.parse(decryptedString)
        for (const key of this._ignore) {
          // patch decrypted doc with ignored fields
          if (key in doc) decrypted[key] = doc[key]
        }
        return decrypted
      }
    })
  },
  removeCrypto: function () {
    delete this._crypt
  }
}

// istanbul ignore next
if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(module.exports)
}
