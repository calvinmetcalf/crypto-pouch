const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = require('tweetnacl-util')
const { secretbox, hash, randomBytes } = require('tweetnacl')
const { transform } = require('transform-pouch')

const IGNORE = ['_id', '_rev', '_deleted']

class Crypt {
  constructor (password) {
    if (!password) { throw new Error('A password is required for encryption or decryption.') }
    this._key = hash(decodeUTF8(password)).slice(0, secretbox.keyLength)
  }

  async encrypt (plaintext) {
    const nonce = randomBytes(secretbox.nonceLength)
    const messageUint8 = decodeUTF8(plaintext)
    const box = secretbox(messageUint8, nonce, this._key)
    const fullMessage = new Uint8Array(nonce.length + box.length)
    fullMessage.set(nonce)
    fullMessage.set(box, nonce.length)
    const base64FullMessage = encodeBase64(fullMessage)
    return base64FullMessage
  }

  async decrypt (messageWithNonce) {
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce)
    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength)
    const message = messageWithNonceAsUint8Array.slice(
      secretbox.nonceLength,
      messageWithNonce.length
    )
    const decrypted = secretbox.open(message, nonce, this._key)
    if (!decrypted) {
      throw new Error('Could not decrypt!')
    } else {
      return encodeUTF8(decrypted)
    }
  }
}

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
