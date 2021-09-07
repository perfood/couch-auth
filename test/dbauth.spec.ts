'use strict';
import { expect } from 'chai';
import nano from 'nano';
import request from 'superagent';
import { ConfigHelper } from '../src/config/configure';
import { DBAuth } from '../src/dbauth';
import seed from '../src/design/seed';
import { CouchDbAuthDoc, DocumentScope, SlUserDoc } from '../src/types/typings';
import { getDBURL } from '../src/util';
import { config } from './test.config';

const dbUrl = getDBURL(config.dbServer as any);
const couch = nano({ url: dbUrl, parseUrl: false });

couch.db.create('cane_test_users');
couch.db.create('cane_test_keys');
couch.db.create('cane_test_test');
const userDB: DocumentScope<SlUserDoc> = couch.db.use('cane_test_users');
const keysDB: DocumentScope<CouchDbAuthDoc> = couch.db.use('cane_test_keys');
const testDB = couch.db.use('cane_test_test');

const userDesign = require('../lib/design/user-design');

const testUser = {
  _id: 'colinskow',
  roles: ['admin', 'user']
};

const userConfigHelper = new ConfigHelper({
  //confirmEmail: true,
  //emailFrom: 'noreply@example.com',
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password
  },
  userDBs: {
    privatePrefix: 'test',
    designDocDir: __dirname + '/ddocs'
  }
});

const dbAuth = new DBAuth(userConfigHelper.config, userDB, keysDB);

describe('DBAuth', () => {
  let key, previous;
  console.log('created test dbs');

  it('should create a database', function () {
    const testDBName = 'sl_test_create_db';
    return checkDBExists(testDBName)
      .then(function (result) {
        expect(result).to.equal(false);
        return dbAuth.createDB(testDBName);
      })
      .then(function () {
        return checkDBExists(testDBName);
      })
      .then(function (result) {
        expect(result).to.equal(true);
        return couch.db.destroy(testDBName);
      });
  });

  it('should generate a database access key', async () => {
    previous = Promise.resolve();
    await seed(userDB, userDesign);
    await userDB.get('_design/auth');
    /**  @type {import('../types/typings').CouchDbAuthDoc}  */
    const newKey = await dbAuth.storeKey(
      testUser._id,
      'testkey',
      'testpass',
      Date.now() + 60000,
      testUser.roles,
      'local'
    );
    key = newKey;
    expect(key._id).to.be.a('string');
    const doc = await keysDB.get('org.couchdb.user:' + key._id);
    expect(doc.expires).to.equal(key.expires);
  });

  it('should remove a database access key', function () {
    return previous
      .then(function () {
        return dbAuth.removeKeys('testkey');
      })
      .then(function () {
        return keysDB.get('org.couchdb.user:testkey');
      })
      .then(function () {
        throw new Error('Failed to delete testkey');
      })
      .catch(function (err) {
        if (
          err.reason &&
          (err.reason === 'deleted' || err.reason === 'missing') &&
          err.statusCode === 404
        )
          return;
        throw err;
      });
  });

  it('should authorize database keys', function () {
    return previous
      .then(function () {
        return dbAuth.authorizeKeys(testDB, ['key1', 'key2']);
      })
      .then(function () {
        return testDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names[0]).to.equal('key1');
        expect(secDoc.members.names[1]).to.equal('key2');
      });
  });

  it('should only authorize keys once', function () {
    return previous
      .then(function () {
        return dbAuth.authorizeKeys(testDB, ['key1', 'key2']);
      })
      .then(function () {
        return testDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(2);
      });
  });

  it('should deauthorize keys', function () {
    return previous
      .then(function () {
        return dbAuth.deauthorizeKeys(testDB, ['key1', 'key2']);
      })
      .then(function () {
        return testDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
      });
  });

  it('should create a new user database', function () {
    const userDoc = {
      _id: '006a2325759840edb2710adc3670b80f',
      session: {
        key1: { expires: Date.now() + 50000 },
        key2: { expires: Date.now() + 50000 }
      }
    };
    let newDB;
    return previous
      .then(function () {
        return dbAuth.addUserDB(
          // @ts-ignore
          userDoc,
          'personal',
          ['test'],
          'private',
          ['admin_role'],
          ['member_role']
        );
      })
      .then(async function (finalDBName) {
        expect(finalDBName).to.equal(
          'test_personal$006a2325759840edb2710adc3670b80f'
        );
        newDB = couch.db.use(finalDBName);
        // console.log('DB created, retrieving security doc.');
        return newDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.admins.roles[secDoc.admins.roles.length - 1]).to.equal(
          'admin_role'
        );
        expect(secDoc.members.roles[secDoc.admins.roles.length - 1]).to.equal(
          'member_role'
        );
        expect(secDoc.members.names[1]).to.equal('key2');
        return newDB.get('_design/test');
      })
      .then(function (design) {
        // console.log('Got design: ', JSON.stringify(design));
        expect(design.views.mytest.map).to.be.a('string');
      })
      .finally(() =>
        couch.db.destroy('test_personal$006a2325759840edb2710adc3670b80f')
      );
  });

  it('should delete all expired keys', function () {
    const now = Date.now();
    let db1, db2;
    const user1 = {
      _id: 'testuser1',
      session: {
        oldkey1: { expires: now + 50000 },
        goodkey1: { expires: now + 50000 }
      },
      personalDBs: {
        test_expiretest$testuser1: {
          permissions: null,
          name: 'expiretest'
        }
      }
    };

    const user2 = {
      _id: 'testuser2',
      session: {
        oldkey2: { expires: now + 50000 },
        goodkey2: { expires: now + 50000 }
      },
      personalDBs: {
        test_expiretest$testuser2: {
          permissions: null,
          name: 'expiretest'
        }
      }
    };

    return previous
      .then(function () {
        const promises = [];
        // Save the users
        promises.push(userDB.bulk({ docs: [user1, user2] }));
        // Add their personal dbs
        // @ts-ignore
        promises.push(dbAuth.addUserDB(user1, 'expiretest')); // @ts-ignore
        promises.push(dbAuth.addUserDB(user2, 'expiretest'));
        // Store the keys
        promises.push(
          dbAuth.storeKey(
            'testuser1',
            'testuser1uid',
            'oldkey1',
            'password',
            user1.session.oldkey1.expires,
            ['user'],
            'local'
          )
        );
        promises.push(
          dbAuth.storeKey(
            'testuser1',
            'testuser1uid',
            'goodkey1',
            'password',
            user1.session.goodkey1.expires,
            ['user'],
            'local'
          )
        );
        promises.push(
          dbAuth.storeKey(
            'testuser2',
            'testuser2uid',
            'oldkey2',
            'password',
            user2.session.oldkey2.expires,
            ['user'],
            'local'
          )
        );
        promises.push(
          dbAuth.storeKey(
            'testuser2',
            'testuser2uid',
            'goodkey2',
            'password',
            user2.session.goodkey2.expires,
            ['user'],
            'local'
          )
        );
        return Promise.all(promises);
      })
      .then(function () {
        // Now we will expire the keys
        const promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        return Promise.all(promises);
      })
      .then(function (docs) {
        docs[0].session.oldkey1.expires = 100;
        docs[1].session.oldkey2.expires = 100;
        return userDB.bulk({ docs: docs });
      })
      .then(function () {
        // Now we will remove the expired keys
        return dbAuth.removeExpiredKeys();
      })
      .then(async function () {
        // Fetch the user docs to inspect them
        db1 = couch.db.use('test_expiretest$testuser1');
        db2 = couch.db.use('test_expiretest$testuser2');
        const promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        promises.push(keysDB.get('org.couchdb.user:goodkey1'));
        promises.push(keysDB.get('org.couchdb.user:goodkey2'));
        promises.push(db1.get('_security'));
        promises.push(db2.get('_security'));
        return Promise.all(promises);
      })
      .then(function (docs) {
        // Sessions for old keys should have been deleted, unexpired keys should be there
        expect(docs[0].session.oldkey1).to.be.an('undefined');
        expect(docs[0].session.goodkey1.expires).to.be.a('number');
        expect(docs[1].session.oldkey2).to.be.an('undefined');
        expect(docs[1].session.goodkey2.expires).to.be.a('number');
        // The unexpired keys should still be in the keys database
        expect(docs[2].user_id).to.equal('testuser1');
        expect(docs[3].user_id).to.equal('testuser2');
        // The security document for each personal db should contain exactly the good keys
        expect(docs[4].members.names.length).to.equal(1);
        expect(docs[4].members.names[0]).to.equal('goodkey1');
        expect(docs[5].members.names.length).to.equal(1);
        expect(docs[5].members.names[0]).to.equal('goodkey2');
        // Now we'll make sure the expired keys have been deleted from the users database
        const promises = [];
        promises.push(keysDB.get('org.couchdb.user:oldkey1'));
        promises.push(keysDB.get('org.couchdb.user:oldkey2'));
        return Promise.allSettled(promises);
      })
      .then(function (results) {
        expect(results[0].status).to.equal('rejected');
        expect(results[1].status).to.equal('rejected');
      })
      .finally(() =>
        // Finally clean up
        Promise.all([
          couch.db.destroy('test_expiretest$testuser1'),
          couch.db.destroy('test_expiretest$testuser2')
        ])
      );
  });

  it('should cleanup databases', function () {
    return previous.finally(function () {
      return Promise.all([
        couch.db.destroy('cane_test_users'),
        couch.db.destroy('cane_test_keys'),
        couch.db.destroy('cane_test_test')
      ]);
    });
  });
});

function checkDBExists(dbname) {
  const finalUrl = dbUrl + '/' + dbname;
  return request.get(finalUrl).then(
    function (res) {
      const result = JSON.parse(res.text);
      if (result.db_name) {
        return Promise.resolve(true);
      }
    },
    function (err) {
      if (err.status === 404) {
        return Promise.resolve(false);
      }
    }
  );
}
