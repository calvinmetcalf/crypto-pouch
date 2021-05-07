const Crypt = require('garbados-crypt')
const { transform } = require('transform-pouch')

const IGNORE = [
  '_id',
  '_rev',
  '_conflicts',
  '_deleted_conflicts',
  '_deleted',
  '_local_seq',
  '_revisions',
  '_revs_info'
]

module.exports = {
  transform,
  crypto: function (password, options = {}) {
    if (typeof password === 'object') {
      // handle `db.crypto({ password, ...options })`
      options = password
      password = password.password
    }
    // setup ignore list
    this._ignore = IGNORE.concat(options.ignore || [])
    // setup crypto helper
    this._crypt = new Crypt(password)
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
          encrypted[key] = doc[key]
        }
        encrypted.payload = await this._crypt.encrypt(JSON.stringify(doc))
        return encrypted
      },
      outgoing: async (doc) => {
        // if no crypt, ex: after .removeCrypto(), just return the doc
        if (!this._crypt) { return doc }
        const decryptedString = await this._crypt.decrypt(doc.payload)
        const decrypted = JSON.parse(decryptedString)
        return decrypted
      }
    })
  },
  removeCrypto: function () {
    delete this._crypt
  }
}

if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(module.exports)
}
