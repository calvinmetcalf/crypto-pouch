crypto pouch [![Build Status](https://travis-ci.org/calvinmetcalf/crypto-pouch.svg)](https://travis-ci.org/calvinmetcalf/crypto-pouch)
===

Plugin to encrypt a PouchDB/CouchDB database.

```js
var db = new PouchDB('my_db');

db.crypto(password);
// all done, docs should be transparently encrypted/decrypted

db.removeCrypto();
// will no longer encrypt decrypt your data
```

It encrypts with the AES-GCM using [native crypto](https://github.com/calvinmetcalf/native-crypto) which prefers the native version in node or the web crypto version in the browser, falling back to the version from [crypto browserify](https://github.com/crypto-browserify/crypto-browserify) if no native version exists. [Chacha20-Poly1305](https://github.com/calvinmetcalf/chacha20poly1305) is also available and previous versions defaulted to this algorithm. You might consider using this if your app will primarily be used in browsers that don't support the web crypto api (e.g. safari).

**Note**: Attachments cannot be encrypted at this point. Use `{ignore: '_attachments'}` to leave attachments unencrypted. Also note that `db.putAttachment` / `db.getAttachment` are not supported. Use `db.put` and `db.get({binary: true, attachment: true})` instead. ([#18](https://github.com/calvinmetcalf/crypto-pouch/issues/13)).

This only encrypts the contents of documents, NOT THE ID (or rev).  So if you have a document with the id `plan_to_screw_over_db_admin`, while this plugin will happily encrypt that document, that may not be as helpful as you'd want it to be.

Usage
-------

This plugin is hosted on npm. To use in Node.js:

```bash
npm install crypto-pouch
```

If you want to use it in the browser, download [the browserified version from wzrd.in](http://wzrd.in/standalone/crypto-pouch) and then include it after `pouchdb`:

```html
<script src="pouchdb.js"></script>
<script src="pouchdb.crypto-pouch.js"></script>
```

API
--------


### db.crypto(password [, options])

Set up encryption on the database.

If the second argument is an object:

- `options.ignore`  
  String or Array of Strings of properties that will not be encrypted.  
- `options.digest`  
  Any of `sha1`, `sha256`, `sha512` (default).
- `options.algorithm`
  Valid options are `chacha20` and `aes-gcm` (default).
- `iterations`
  How many iterations of pbkdf2 to perform, defaults to 100000 (1000 in older versions).
- `key`
  If passed a 32 byte buffer then this will be used as the key instead of it being generated from the password. **Warning** this buffer will be randomized when encryption is removed so pass in a copy of the buffer if that will be a problem.
- `password`
  You can pass the options object as the first param if you really want and pass in the password in as an option.
- `cb`
  A function you can pass in to get the derived key back called with 2 parameters, an error if there is one and the key if no error.  **Warning** this buffer will be randomized when encryption is removed copy it or convert it to a string if that will be a problem.

### db.removeCrypto()

Disables encryption on the database and randomizes the key buffer.

Details
===

If you replicate to another database, it will decrypt before sending it to
the external one. So make sure that one also has a password set as well if you want
it encrypted too.

If you change the name of a document, it will throw an error when you try
to decrypt it. If you manually move a document from one database to another,
it will not decrypt correctly.  If you need to decrypt it a file manually
you will find a local doc named `_local/crypto` in the database. This doc has
fields named `salt` which is a hex-encoded buffer, `digest` which is a string, `iterations` which is an integer to use and `algo` which is the encryption algorithm. Run pbkdf2 your password with the
salt, digest and iterations values from that document as the parameters generate
a 32 byte (256 bit) key; that is the key for decoding documents.  If digest, iterations, or algo are not on the local document due to it being created with an older version of the library, use 'sha256', 1000, and 'chacha20' respectively.

Each document has 3 relevant fields: `data`, `nonce`, and `tag`.
`nonce` is the initialization vector to give to the encryption algorithm in addition to the key
you generated. Pass the document `_id` as additional authenticated data and the tag
as the auth tag and then decrypt the data.  If it throws an error, then you either
screwed up or somebody modified the data.

Examples
===

Derive key from password and salt
---

```js
db.get('_local/crypto').then(function (doc) {
  return new Promise(function (resolve, reject) {
    crypto.pbkdf2(password, doc.salt, doc.iterations, 256/8, doc.digest, function (err, key) {
      if (err) {
        return reject(err);
      }
      resolve(key);
    });
  });
}).then(function (key) {
  // you have the key
});
```

Decrypt a document encrypted with chacha
---

```js
var chacha = require('chacha');

db.get(id).then(function (doc) {
  var decipher = chacha.createDecipher(key, new Buffer(doc.nonce, 'hex'));
  decipher.setAAD(new Buffer(doc._id));
  decipher.setAuthTag(new Buffer(doc.tag, 'hex'));
  var out = decipher.update(new Buffer(doc.data, 'hex')).toString();
  decipher.final();
  // parse it AFTER calling final
  // you don't want to parse it if it has been manipulated
  out = JSON.parse(out);
  out._id = doc._id;
  out._rev = doc._rev;
  return out;
});
```

Decrypt a document encrypted with aes-gcm
---

```js
var decrypt = require('native-crypto/decrypt');

db.get(id).then(function (doc) {
  var encryptedData =  Buffer.concat([
    new Buffer(doc.data, 'hex'),
    new Buffer(doc.tag, 'hex')
  ]);
  return decrypt(key, new Buffer(doc.nonce, 'hex'), encryptedData, new Buffer(doc._id)).then(function (resp) {
    var out = JSON.parse(resp.toString());
    out._id = doc._id;
    out._rev = doc._rev;
    return out;
  });
});
```
