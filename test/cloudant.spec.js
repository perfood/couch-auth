'use strict';
const expect = require('chai').expect;
const CloudantAdapter = require('../lib/dbauth/cloudant').CloudantAdapter;
const cloudant = new CloudantAdapter();
const utils = require('../lib/util');
const nano = require('nano')(utils.getCloudantURL());
const testDBName = 'temp_test';
/** @type {import('nano').DocumentScope<any>} */
let testDB;
let previous;

describe('Cloudant', function () {
  previous = Promise.resolve();

  before(function () {
    return previous.then(async () => {
      await nano.db.create(testDBName);
      testDB = nano.use(testDBName);
      return testDB;
    });
  });

  after(function () {
    this.timeout(5000);
    return previous.finally(function () {
      return nano.db.destroy(testDBName);
    });
  });

  it('should generate an API key', function () {
    this.timeout(5000);
    return previous
      .then(function () {
        return cloudant.getAPIKey();
      })
      .then(function (result) {
        expect(result.ok).to.equal(true);
        expect(result.key).to.be.a('string');
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
