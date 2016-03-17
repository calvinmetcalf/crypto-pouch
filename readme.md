crypto pouch [![Build Status](https://travis-ci.org/calvinmetcalf/crypto-pouch.svg)](https://travis-ci.org/calvinmetcalf/crypto-pouch)
===

Plugin to encrypt a PouchDB/CouchDB database.

```js
var db = new PouchDB('my_db');

db.crypto(password).then(function (publicKey) {
  // all done, you got a public key
});

db.removeCrypto(); // will no longer encrypt decrypt your data
```

It currently encrypts with the [Chacha20-Poly1305](https://github.com/calvinmetcalf/chacha20poly1305) algorithm, but this may be changed
to AES256-GCM when Node 0.12.0 drops.

Usage
-------

This plugin is hosted on npm. To use in Node.js:

```bash
npm install crypto-pouch
```

If you want to use it in the browser, download [the browserified version from wzrd.in](http://wzrd.in/bundle/crypto-pouch) and then include it after `pouchdb`:

```html
<script src="pouchdb.js"></script>
<script src="pouchdb.crypto-pouch.js"></script>
```

API
--------


### db.crypto(password)

Set up encryption on the database.


### db.removeCrypto()

Disables encryption on the database.

Details
===

If you replicate to another database, it will decrypt before sending it to
the external one. So make sure that one also has a password set as well if you want
it encrypted too.

If you change the name of a document, it will throw an error when you try
to decrypt it. If you manually move a document from one database to another,
it will not decrypt correctly.  If you need to decrypt it a file manually
you will find a local doc named `_local/crypto` in the database. This doc has a field
named `salt` which is a hex-encoded buffer. Run on your password with that as salt
for 1000 iterations to generate a 32 byte (256 bit) key; that is the key
for decoding documents.

Each document has 3 relevant fields: `data`, `nonce`, and `tag`.
`nonce` is the initialization vector to give to chacha20 in addition to the key
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
    crypto.pbkdf2(password, doc.salt, 1000, 256/8, function (err, key) {
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

Decrypt a document
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

Diffie Hellman
===

Diffie Hellman is an algorithm that allows 2 parties to create a secure key while only communicating via public channels.  I'm not sure how useful this option will be in practice but I have a vague notion of how it might be useful.

For instance suppose Arthur needed some data from Beatrix but they could only communicate over twitter and pastebin. Arthur could run in node (version 0.11 or higher)

```js
var crypto = require('crypto');
var dh = crypto.getDiffieHellman('modp14');
dh.generateKeys();
console.log('public', dh.getPublicKey('hex'));
console.log('private', dh.getPrivateKey('hex'));
```

Arthur could then save his private key and post on pastebin the public key and `modp14`.

Beatrix then creates a pouchdb with the cryto plugin and opens it with

```js
db.crypto(new Buffer('the public key', 'hex'), 'modp14').then(function (public) {
  console.log('public', public.toString('hex'));
  // fill it up with data
});
```

then Beatrix could zip up the leveldb folder and include a note with the public key, and post it somewhere.

Arthur could then run

```js
var crypto = require('crypto');
var dh = crypto.createDiffieHellman(crypto.getDiffieHellman('modp14').getPrime());
// the above throws an error in node 0.10 due to a bug
dh.setPrivateKey('private key from earlier', 'hex');
dh.generateKeys();
var secret = dh.computeSecret('public key from Beatrix', 'hex');
```

and Arthur could then use that to open the database.

To run it in node 0.10 Arthur would need to generate a custom prime with

```js
var crypto = require('crypto');
var dh = crypto.createDiffieHellman(512);
// this can be very slow
dh.generateKeys();
console.log('public', dh.getPublicKey('hex'));
console.log('private', dh.getPrivateKey('hex'));
console.log('prime', dh.getPrime('hex'));
```

and send the prime to Beatrix who would run

```js
db.crypto(new Buffer('the public key', 'hex'), new Buffer('prime', 'hex')).then(function (public) {
  console.log('public', public.toString('hex'));
  // fill it up with data
});
```

and Arthur would run

```js
var crypto = require('crypto');
var dh = crypto.createDiffieHellman(new Buffer('prime', 'hex'));
// the above throws an error in node 0.10 due to a bug
dh.setPrivateKey('private key from earlier', 'hex');
dh.generateKeys();
var secret = dh.computeSecret('public key from Beatrix', 'hex');
```