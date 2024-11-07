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
    const trySetup = async () => {
      // try saving credentials to a local doc
      try {
        // first we try to get saved creds from the local doc
        const { exportString } = await this.get(LOCAL_ID)
        this._crypt = await Crypt.import(password, exportString)
      } catch (err) {
        // istanbul ignore else
        if (err.status === 404) {
          // but if the doc doesn't exist, we do first-time setup
          this._crypt = new Crypt(password)
          const exportString = await this._crypt.export()
          try {
            await this.put({ _id: LOCAL_ID, exportString })
          } catch (err2) {
            // istanbul ignore else
            if (err2.status === 409) {
              // if the doc was created while we were setting up,
              // try setting up again to retrieve the saved credentials.
              await trySetup()
            } else {
              throw err2
            }
          }
        } else {
          throw err
        }
      }
    }
    await trySetup()
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
        if (!doc.payload) { return doc }
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
