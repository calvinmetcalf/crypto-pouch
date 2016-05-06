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
  db.crypto('password');
  db.put({foo: 'bar'}, 'baz').then(function () {
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
  db.crypto('password');
  db.get('baz').then(function (resp) {
    t.equals(resp.foo, 'bar', 'decrypts data');
  });
});
test('changes', function (t) {
  t.plan(7);
  var dbName = 'five';
  var db = new PouchDB(dbName, {db: memdown});
  db.changes({ live: true,  include_docs: true}).on('change', function (d) {
    t.ok(true, 'changes called');
  })
  db.crypto('password');
  db.put({foo: 'bar'}, 'baz').then(function () {
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
test('ignore: _attachments', function (t) {
  t.plan(1);
  var dbName = 'six';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password', {ignore: '_attachments'})
  db.put({
    _id: 'id-12345678',
    _attachments: {
      'att.txt': {
        content_type: 'text/plain',
        data: 'TGVnZW5kYXJ5IGhlYXJ0cywgdGVhciB1cyBhbGwgYXBhcnQKTWFrZS' +
              'BvdXIgZW1vdGlvbnMgYmxlZWQsIGNyeWluZyBvdXQgaW4gbmVlZA=='
      }
    }
  }).then(function () {
    return db.get('id-12345678', {
      attachments: true,
      binary: true
    });
  }).then(function (doc) {
    t.ok(Buffer.isBuffer(doc._attachments['att.txt'].data), 'returns _attachments as Buffers');
  })
  .catch(t.error);
})
test('throws error when document has attachments', function (t) {
  t.plan(1);
  var dbName = 'eight';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password')
  db.put({
    _id: 'id-12345678',
    _attachments: {
      'att.txt': {
        content_type: 'text/plain',
        data: 'TGVnZW5kYXJ5IGhlYXJ0cywgdGVhciB1cyBhbGwgYXBhcnQKTWFrZS' +
              'BvdXIgZW1vdGlvbnMgYmxlZWQsIGNyeWluZyBvdXQgaW4gbmVlZA=='
      }
    }
  }).then(function () {
    t.error('does not throw error');
  }).catch(function (e) {
    t.ok(/Attachments cannot be encrypted/.test(e.message), 'throws error');
  })
})
test('options.digest with sha512 default', function (t) {
  t.plan(2);
  var db1 = new PouchDB('ten', {db: memdown});
  var db2 = new PouchDB('eleven', {db: memdown});

  // simulate previously doc created with {digest: sha512}
  var docSha256 = {
    nonce: '619cf4a32914bc9b5ca26ddf',
    data: 'bdc160a9ff46151af37ccd6e20',
    tag: '1d082c358bc4cda3e8249bb0bb19eb3e',
    _id: 'baz'
  };
  var cryptoDoc = {
    _id: '_local/crypto',
    salt: 'f5c011aea21f25b9e975dbacbe38d235'
  };
  db1.bulkDocs([docSha256, cryptoDoc]).then(function () {
    db1.crypto('password');
    return db1.get('baz');
  }).then(function (doc) {
    t.equals(doc.foo, 'bar', 'returns doc for same write / read digest');
  });

  db2.bulkDocs([docSha256, cryptoDoc]).then(function () {
    db2.crypto('password', {digest: 'sha512'});
    return db2.get('baz');
  }).then(function () {
    t.error('does not throw error');
  }).catch(function (err) {
    t.ok(err, 'throws error for different write / read digest');;
  });
});
