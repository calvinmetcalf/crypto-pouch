'use strict';
var test = require('tape');
var PouchDB = require('pouchdb');
var memdown = require('memdown');
var createECDH = require('create-ecdh')
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
    console.log('nooo!', e.stack);
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
test('ec', function(t) {
  var publicKey = createECDH('secp256k1');
  publicKey.generateKeys();
  publicKey = publicKey.getPrivateKey('hex');
  t.test('basic', function (t) {
    t.plan(4);
    var dbName = 'two';
    var db = new PouchDB(dbName, {db: memdown});
    db.crypto(new Buffer(publicKey, 'hex')).then(function () {
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
      console.log('nooo!', e.stack);
    });
  });
  t.test('reopen', function (t) {
    t.plan(1);
    var dbName = 'two';
    var db = new PouchDB(dbName, {db: memdown});
    db.crypto(new Buffer(publicKey, 'hex')).then(function () {
      return db.get('baz');
    }).then(function (resp) {
      t.equals(resp.foo, 'bar', 'decrypts data');
    });
  });
});
