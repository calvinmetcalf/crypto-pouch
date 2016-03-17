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
