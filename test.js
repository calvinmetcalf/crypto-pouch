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
  db.put({foo: 'bar', _id: 'baz'}).then(function () {
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
  db.put({foo: 'bar', _id: 'baz'}).then(function () {
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
      with: 'feeling',
      _id: d.id,
      _rev: d.rev});
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
  t.plan(1);
  var db = new PouchDB('ten', {db: memdown});

  // simulate previously doc created with {digest: 'sha512'}
  var docSha256 = {
    nonce: '27860742f613568f2e1f3945',
    data: 'b4f1c89c024092b84cb7de1304',
    tag: 'b7b8397c65cea0e9203ff9a7069f3cc5',
    _id: 'baz'
  };
  var cryptoDoc = {
    _id: '_local/crypto2',
    algorithm: 'aes-256-gcm',
    digest: 'sha512',
    salt: '2bdfe3c9f12e80728fd9978e462e4d39'
  };
  db.bulkDocs([docSha256, cryptoDoc]).then(function () {
    db.crypto('password'/*, {digest: 'sha512'}*/);
    return db.get('baz');
  }).then(function (doc) {
    t.equals(doc.foo, 'bar', 'returns doc for same write / read digest');
  }).catch(function (err) {
    t.error(err, 'threw an error');
  });
});
test('put with _deleted: true', function (t) {
  t.plan(1);
  var dbName = 'twelve';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto('password')
  var doc = {_id: 'baz', foo: 'bar'}
  db.put(doc).then(function (result) {
    doc._rev = result.rev
    doc._deleted = true
    return db.put(doc)
  }).then(function () {
    return db.get('baz')
  }).then(function () {
    t.error('should not find doc after delete');
  }).catch(function (err) {
    t.equal(err.status, 404, 'cannot find doc after delete')
  })
})
