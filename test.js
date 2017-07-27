var test = require('tape');
var PouchDB = require('pouchdb');
var memdown = require('memdown');
var Promise = require('pouchdb-promise');
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
  db.changes({ live: true,  include_docs: true}).on('change', function () {
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
      _id: d.id,
      _rev: d.rev,
      once: 'more',
      with: 'feeling'
    });
  }).then(function () {
    return db.allDocs({include_docs: true});
  }).then(function () {
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
    t.ok(err, 'throws error for different write / read digest');
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
test('pass key in explicitly', function (t) {
  t.plan(1);
  var db = new PouchDB('thirteen', {db: memdown});

  var ourDoc = {
    nonce: '000000000000000000000000',
    data: 'e42581d13a730258fadbe55e0e',
    tag: 'b52f7f0f3e2926d7ee43f867d2c597e2',
    _id: 'baz'
  };
  db.bulkDocs([ourDoc]).then(function () {
    db.crypto({key: new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')});
    return db.get('baz');
  }).then(function (doc) {
    t.equals(doc.foo, 'bar', 'returns doc for same write / read digest');
  }).catch(function (e) {
    t.error(e);
  });
});
test('pass key in explicitly as arr buff', function (t) {
  t.plan(1);
  var db = new PouchDB('tweentyteen', {db: memdown});

  var ourDoc = {
    nonce: '000000000000000000000000',
    data: 'e42581d13a730258fadbe55e0e',
    tag: 'b52f7f0f3e2926d7ee43f867d2c597e2',
    _id: 'baz'
  };
  db.bulkDocs([ourDoc]).then(function () {
    db.crypto({key: new Uint8Array(new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex'))});
    return db.get('baz');
  }).then(function (doc) {
    t.equals(doc.foo, 'bar', 'returns doc for same write / read digest');
  }).catch(function (e) {
    t.error(e);
  });
});
test('wrong password throws error', function (t) {
  t.plan(1);
  var db = new PouchDB('thirteen', {db: memdown});

  var ourDoc = {
    nonce: '000000000000000000000000',
    data: 'e42581d13a730258fadbe55e0e',
    tag: 'b52f7f0f3e2926d7ee43f867d2c597e2',
    _id: 'baz'
  };
  db.bulkDocs([ourDoc]).then(function () {
    db.crypto('broken');
    return db.get('baz');
  }).then(function (doc) {
    t.notEqual(doc.foo, 'bar', 'returns doc for same write / read digest');
  }).catch(function (e) {
    t.ok(e);
  });
});
test('plain options object', function (t) {
  t.plan(4);
  var dbName = 'fourteen';
  var db = new PouchDB(dbName, {db: memdown});
  db.crypto({password: 'password'});
  db.put({_id: 'baz', foo: 'bar'}).then(function () {
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
test('get key explicitly', function (t) {
  t.plan(3);
  var db = new PouchDB('fifteen', {db: memdown});
  var key;
  var docs = [
    { _id: '_local/crypto',
      salt: '0dac47a196e46680a359c9c18da0bc83',
      digest: 'sha256',
      iterations: 100000}
  ];
  db.bulkDocs(docs).then(function () {
    db.crypto('password', {
      cb: function (err, resp) {
        t.error(err);
        key = resp.toString('base64');
        t.equals(key, 'jr9j3Krslfck3UkxjiCNYI4hoKQWesoquw11yypC528=');
      }
    });
    return db.put({
      _id: 'baz',
      foo: 'bar'
    });
  }).then(function () {
    db.removeCrypto();
    db.crypto({key: new Buffer(key, 'base64')});
    return db.get('baz');
  })
  .then(function (doc) {
    t.equals(doc.foo, 'bar', 'decrypts data');
  }).catch(function (e) {
    t.error(e);
  });
});
