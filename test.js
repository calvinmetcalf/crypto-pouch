var test = require('tape');
var PouchDB = require('pouchdb');
var memdown = require('memdown');
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