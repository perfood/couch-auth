'use strict';
const PouchDB = require('pouchdb');
const expect = require('chai').expect;
const CloudantAdapter = require('../src/dbauth/cloudant').CloudantAdapter;
const cloudant = new CloudantAdapter();
// todo: test with nano instead!

const cloudantUrl =
  'https://' +
  process.env.CLOUDANT_USER +
  ':' +
  process.env.CLOUDANT_PASS +
  '@' +
  process.env.CLOUDANT_USER +
  '.cloudant.com';
let testDB;
let previous;

describe('Cloudant', function () {
  let apiKey;

  previous = Promise.resolve();

  before(function () {
    return previous.then(function () {
      testDB = new PouchDB(cloudantUrl + '/temp_test');
      return testDB;
    });
  });

  after(function () {
    this.timeout(5000);
    return previous.finally(function () {
      return testDB.destroy();
      // return Promise.resolve();
    });
  });

  it('should generate an API key', function () {
    this.timeout(5000);
    return previous
      .then(function () {
        return cloudant.getAPIKey(testDB);
      })
      .then(function (result) {
        expect(result.ok).to.equal(true);
        expect(result.key).to.be.a('string');
        apiKey = result.key;
      });
  });

  it('should authorize keys', function () {
    this.timeout(10000);
    return previous
      .then(function () {
        return cloudant.authorizeKeys('test_user', testDB, [
          'abc123',
          'def456'
        ]);
      })
      .then(function () {
        return cloudant.getSecurityCloudant(testDB);
      })
      .then(function (secDoc) {
        expect(secDoc.cloudant.abc123[0]).to.equal('user:test_user');
        expect(secDoc.cloudant.abc123[1]).to.equal('_reader');
      });
  });

  it('should deauthorize a key', function () {
    this.timeout(10000);
    return previous
      .then(function () {
        return cloudant.deauthorizeKeys(testDB, 'abc123');
      })
      .then(function () {
        return cloudant.getSecurityCloudant(testDB);
      })
      .then(function (secDoc) {
        expect(secDoc.cloudant.abc123).to.be.an('undefined');
        expect(secDoc.cloudant.def456[1]).to.equal('_reader');
      });
  });
});
