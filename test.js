var test = require('tape');
var PouchDB = require('pouchdb');
var memdown = require('memdown');
var Promise = require('pouchdb-promise');
var crypto = require('crypto');
PouchDB.plugin(require('./'));
test('basic', function (t) {
  t.plan(4);
  var dbName = 'one';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password').then(function () {
    return db.put({foo: 'bar'}, 'baz');
  }).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar', 'decrypts data');
    db.removeCrypto();
    return db.get('baz');
  }).then(function (doc) {
    t.ok(doc.nonce, 'has nonce');
    t.ok(doc.tag, 'has tag');
    t.ok(doc.data, 'has data');
  }).catch(function (e) {
    t.error(e);
  });
});
test('reopen', function (t) {
  t.plan(1);
  var dbName = 'one';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password').then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar', 'decrypts data');
  });
});
var pub, dh;
test('dh', function (t) {
  t.plan(5);
  var dbName = 'two';
  var db = new PouchDB(dbName, {db: memdown});
  dh = crypto.getDiffieHellman('modp5');
  dh.generateKeys();
  db.crypto(dh.getPublicKey(), 'modp5').then(function (public) {
    t.ok(public, 'get public key');
    pub = public;
    return db.put({foo: 'bar2'}, 'baz');
  }).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar2', 'decrypts data');
    db.removeCrypto();
    return db.get('baz');
  }).then(function (doc) {
    t.ok(doc.nonce, 'has nonce');
    t.ok(doc.tag, 'has tag');
    t.ok(doc.data, 'has data');
  });
});
test('reopen', function (t) {
  t.plan(1);
  var dbName = 'two';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto(dh.computeSecret(pub)).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar2', 'decrypts data');
  });
});
var pub, dh;
test('dh and prime', function (t) {
  t.plan(5);
  var dbName = 'three';
  var prime = crypto.createDiffieHellman(512).getPrime();
  var db = new PouchDB(dbName, {db: memdown});
  dh = crypto.createDiffieHellman(prime);
  dh.generateKeys();
  db.crypto(dh.getPublicKey(), prime).then(function (public) {
    t.ok(public, 'get public key');
    pub = public;
    return db.put({foo: 'bar2'}, 'baz');
  }).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar2', 'decrypts data');
    db.removeCrypto();
    return db.get('baz');
  }).then(function (doc) {
    t.ok(doc.nonce, 'has nonce');
    t.ok(doc.tag, 'has tag');
    t.ok(doc.data, 'has data');
  });
});
test('reopen', function (t) {
  t.plan(1);
  var dbName = 'three';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto(dh.computeSecret(pub)).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar2', 'decrypts data');
  });
});
test('changes', function (t) {
  t.plan(7);
  var dbName = 'five';
  var db = new PouchDB(dbName, {db: memdown});
  db.changes({ live: true,  include_docs: true}).on('change', function (d) {
    t.ok(true, 'changes called');
  })
  db.crypto('password').then(function () {
    return db.put({foo: 'bar'}, 'baz');
  }).then(function () {
    return db.get('baz');
  }).then(function (resp) {
    t.equals(resp.foo, 'bar', 'decrypts data');
    return db.post({baz: 'bat'});
  }).then(function (d){
    return new Promise(function (yes) {
      setTimeout(function () {
        yes(d);
      }, 200);
    });
  }).then(function(d) {
    return db.put({
      once: 'more',
      with: 'feeling'
    }, d.id, d.rev);
  }).then(function () {
    return db.allDocs({include_docs: true});
  }).then(function (resp) {
    db.removeCrypto();
    return db.get('baz');
  }).then(function (doc) {
    t.ok(doc.nonce, 'has nonce');
    t.ok(doc.tag, 'has tag');
    t.ok(doc.data, 'has data');
  }).catch(function (e) {
    t.error(e);
  });
});
test('attachments', function (t) {
  t.plan(1);
  var dbName = 'six';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password').then(function () {
    return db.put({
      _id: 'id-12345678',
      _attachments: {
        'att.txt': {
          content_type: 'text/plain',
          data: 'TGVnZW5kYXJ5IGhlYXJ0cywgdGVhciB1cyBhbGwgYXBhcnQKTWFrZS' +
                'BvdXIgZW1vdGlvbnMgYmxlZWQsIGNyeWluZyBvdXQgaW4gbmVlZA=='
        }
      }
    })
  }).then(function () {
    return db.get('id-12345678', {
      attachments: true,
      binary: true
    })
  }).then(function (doc) {
    t.ok(Buffer.isBuffer(doc._attachments['att.txt'].data), 'returns _attachtments as Buffers')
  })
  .catch(t.error)
})
