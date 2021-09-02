# Crypto-Pouch

[![CI](https://github.com/calvinmetcalf/crypto-pouch/actions/workflows/ci.yaml/badge.svg)](https://github.com/calvinmetcalf/crypto-pouch/actions/workflows/ci.yaml)
[![NPM Version](https://img.shields.io/npm/v/crypto-pouch.svg?style=flat-square)](https://www.npmjs.com/package/crypto-pouch)
[![JS Standard Style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/feross/standard)

Plugin to encrypt a PouchDB database.

```js
const PouchDB = require('pouchdb')
PouchDB.plugin(require('crypto-pouch'))

const db = new PouchDB('my_db')

// init; after this, docs will be transparently en/decrypted
db.crypto(password).then(() => {
  // db will now transparently encrypt writes and decrypt reads
  await db.put({ ... })
  // you can disable transparent en/decryption,
  // though encrypted docs remain encrypted
  db.removeCrypto()
})
```

Crypto-Pouch encrypts documents using [TweetNaCl.js](https://github.com/dchest/tweetnacl-js), an [audited](https://cure53.de/tweetnacl.pdf) encryption library. It uses the *xsalsa20-poly1305* algorithm.

**Note**: Attachments cannot be encrypted at this point. Use `{ignore: '_attachments'}` to leave attachments unencrypted. Also note that `db.putAttachment` / `db.getAttachment` are not supported. Use `db.put` and `db.get({binary: true, attachment: true})` instead. ([#18](https://github.com/calvinmetcalf/crypto-pouch/issues/13)).

This only encrypts the contents of documents, **not the \_id or \_rev, nor view keys and values**. This means that `_id` values always remain unencrypted, and any keys or values emitted by views are stored unencrypted as well. If you need total encryption at rest, consider using the PouchDB plugin [ComDB](https://github.com/garbados/comdb) instead.

## Usage

This plugin is hosted on [npm](http://npmjs.com/). To install it in your project:

```bash
$ npm install crypto-pouch
```

## Usage

### async db.crypto(password [, options])

Set up encryption on the database.

- `password`: A string password, used to encrypt documents. Make sure it's good!
- `options.ignore`: Array of strings of properties that will not be encrypted.
- `options.salt`: A string salt, used to manually specify a salt. This will be combined with the `password` to generate the encryption key. Using the same `salt` and `password` for data encrypted across multiple databases will result in the same encrypted output.

You may also pass an options object as the first parameter, like so:

```javascript
db.crypto({ password, ignore: [...] }).then(() => {
  // database will now encrypt writes and decrypt reads
})
```

### db.removeCrypto()

Disables encryption on the database and forgets your password.

## Details

If you replicate to another database, Crypto-Pouch will decrypt documents before
sending them to the target database. Documents received through replication will
be encrypted before being saved to disk.

If you change the ID of a document, Crypto-Pouch will throw an error when you try
to decrypt it. If you manually move a document from one database to another,
it will not decrypt correctly.

Encrypted documents have only one custom property, `payload`, which contains the
encrypted contents of the unencrypted document. So, `{ hello: 'world' }` becomes
`{ payload: '...' }`. This `payload` value is produced by [garbados-crypt](https://github.com/garbados/crypt#garbados-crypt); see that library for more details.

## Development

First, get the source:

```bash
$ git clone git@github.com:calvinmetcalf/crypto-pouch.git
$ cd crypto-pouch
$ npm i
```

Use the test suite:

```bash
$ npm test
```

*When contributing patches, be a good neighbor and include tests!*

## License

See [LICENSE](./LICENSE).
