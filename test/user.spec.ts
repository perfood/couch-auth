import { expect, use } from 'chai';
import events from 'events';
import nano, { DocumentScope } from 'nano';
import { join } from 'path';
import sinon from 'sinon';
import request from 'superagent';
import { v4 as uuidv4, validate as isUUID } from 'uuid';
import { ConfigHelper as Configure } from '../src/config/configure';
import seed from '../src/design/seed';
import { Mailer } from '../src/mailer';
import { CouchDbAuthDoc, SlUserDoc } from '../src/types/typings';
import { User } from '../src/user';
import {
  addProvidersToDesignDoc,
  getDBURL,
  hyphenizeUUID,
  timeoutPromise
} from '../src/util';
import { config } from './test.config';

// Import sinon-chai using require to avoid ES module issues
const sinonChai = require('sinon-chai');
use(sinonChai.default || sinonChai);

const dbUrl = getDBURL(config.dbServer as any);
const couch = nano(dbUrl);

const emitter = new events.EventEmitter();

const userDB: DocumentScope<SlUserDoc> = couch.db.use('superlogin_test_users');
const keysDB: DocumentScope<CouchDbAuthDoc> = couch.db.use(
  'superlogin_test_keys'
);

const testUserForm = {
  name: 'Super',
  username: 'superuser',
  email: 'superuser@example.com',
  password: 'superlogin',
  confirmPassword: 'superlogin',
  age: '32',
  zipcode: 'ABC123'
};
let superuserUUID;
let testUserUUID;
let misterxUUID;
let misterxKey;
let resetToken;
let resetTokenHashed;
let spySendMail;

const emailUserForm = {
  name: 'Awesome',
  email: 'awesome@example.com',
  password: 'supercool',
  confirmPassword: 'supercool'
};

const userConfigHelper = new Configure({
  testMode: {
    noEmail: true
  },
  security: {
    defaultRoles: ['user'],
    disabledRoutes: [],
    userActivityLogSize: 3,
    iterations: [
      [0, 10],
      [1596797642, 10000]
    ],
    userHashing: {
      iterations: 50000,  // Non-default value for testing
      pbkdf2Prf: 'sha256',
      keyLength: 32,
      saltLength: 16
    }
  },
  local: {
    sendConfirmEmail: true,
    requireEmailConfirm: false,
    keepEmailConfirmToken: true,
    sendPasswordChangedEmail: true,
    passwordConstraints: {
      length: {
        minimum: 8,
        message: 'must be at least 8 characters'
      },
      matches: 'confirmPassword'
    },
    // todo: adjust once the old default behaviour works.
    usernameLogin: true,
    emailUsername: false,
    // this is deleted after the 1st two tests. Todo: run in isolation...
    consents: {
      privacy: { minVersion: 2, currentVersion: 3, required: true },
      marketing: { minVersion: 3, currentVersion: 5, required: false }
    }
  },
  mailer: {
    fromEmail: 'noreply@example.com'
  },
  emailTemplates: {
    folder: join(__dirname, '../templates/email'),
    templates: {
      confirmEmail: {
        subject: 'Please confirm your email'
      },
      forgotPassword: {
        subject: 'Your password reset link'
      },
      modifiedPassword: {
        subject: 'Your password has been modified'
      }
    }
  },
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password,
    publicURL: 'https://mydb.example.com'
  },
  userDBs: {
    defaultSecurityRoles: {
      admins: ['admin_role'],
      members: ['member_role']
    },
    model: {
      _default: {
        designDocs: ['test']
      }
    },
    defaultDBs: {
      private: ['usertest']
    },
    privatePrefix: 'test',
    designDocDir: __dirname + '/ddocs'
  },
  providers: {
    facebook: {
      // @ts-ignore todo: differs from config..
      clientID: 'FAKE_ID',
      clientSecret: 'FAKE_SECRET',
      callbackURL: 'http://localhost:5000/auth/facebook/callback'
    }
  },
  userModel: {
    static: {
      modelTest: true
    },
    whitelist: ['age', 'zipcode']
  }
});
const userConfig = userConfigHelper.config;

const req = {
  headers: {
    host: 'example.com'
  },
  protocol: 'http'
};

let createdDBs = ['superlogin_test_users', 'superlogin_test_keys'];

describe('User Model', async function () {
  const mailer = new Mailer(userConfig);
  let user = new User(userConfig, userDB, keysDB, mailer, emitter, couch);
  let userTestDB;
  let previous;
  let verifyEmailToken;

  before(async function () {
    for (const db of createdDBs) {
      try {
        await couch.db.destroy(db);
      } catch (err) {}
    }
    await couch.db.create('superlogin_test_users');
    await couch.db.create('superlogin_test_keys');
    let userDesign = require('../lib/design/user-design');
    userDesign = addProvidersToDesignDoc(userConfig, userDesign);
    previous = Promise.resolve();
    return previous
      .then(function () {
        return seed(userDB, userDesign);
      })
      .then(() => {
        console.log('Database has been prepared.');
        return userDB.get('_design/auth');
      });
  });

  after(function () {
    // 'should destroy all the test databases'
    return previous.finally(async () => {
      console.log('Destroying databases');
      const allDbs = await couch.db.list();
      createdDBs = createdDBs.concat(
        allDbs.filter(db => db.startsWith('test_usertest$'))
      );
      await Promise.all(createdDBs.map(db => couch.db.destroy(db)));
      return Promise.resolve();
    });
  });

  it('should reject a new user with invalid consents', async () => {
    const invalidRequests = [
      user.createUser({
        ...testUserForm,
        consents: { privacy: { version: '2', accepted: true } }
      }),
      user.createUser({
        ...testUserForm,
        consents: { privacy: { version: -1, accepted: true } }
      }),
      user.createUser({
        ...testUserForm,
        consents: {
          privacy: { version: 2, accepted: false },
          marketing: { version: 3, accepted: true }
        }
      }),
      user.createUser({
        ...testUserForm,
        consents: {
          privacy: { version: 3, accepted: true },
          marketing: { version: 1, accepted: true }
        }
      }),
      user.createUser({
        ...testUserForm,
        consents: {
          privacy: { version: 1, accepted: true },
          marketing: { version: 4, accepted: true }
        }
      }),
      user.createUser({
        ...testUserForm,
        consents: {
          privacy: { version: 2, accepted: true },
          marketing: { version: 6, accepted: false }
        }
      })
    ];
    const results = await Promise.allSettled(invalidRequests);
    const invalid = results
      .map((r, i) =>
        r.status === 'fulfilled'
          ? `invalid consent request number ${i} succeeded`
          : undefined
      )
      .filter(r => !!r);
    if (invalid.length) {
      console.error(invalid.length + 'invalid consents requests accepted.');
      throw invalid.join(', ');
    }
    console.log('OK - invalid consents rejected.');
  });

  it('should save a new user with valid consents', async () => {
    try {
      await user.createUser({
        ...testUserForm,
        consents: {
          privacy: { version: 2, accepted: true },
          marketing: { version: 3, accepted: true }
        }
      });
      await timeoutPromise(500); // todo: use emitter instead
      await user.removeUser('superuser');
    } catch (error) {
      console.error('Creation or cleanup failed with: ', error);
      throw error;
    }
  });

  it('should save a new user', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('signup', function (user) {
        expect(isUUID(hyphenizeUUID(user._id))).to.be.true;
        expect(user.key).to.equal('superuser');
        resolve();
      });
    });
    const now = new Date().valueOf();

    return previous
      .then(() => {
        delete userConfig.local.consents;
        delete user.userModel.validate.consents;

        user.onCreate(userDoc => {
          userDoc['onCreate1'] = true;
          return Promise.resolve(userDoc);
        });
        user.onCreate(userDoc => {
          userDoc['onCreate2'] = true;
          return Promise.resolve(userDoc);
        });
        return user.createUser(testUserForm, req);
      })
      .then(newUser => {
        return timeoutPromise(500).then(() => newUser); // todo: use emitter
      })
      .then(newUser => {
        superuserUUID = newUser._id;
        return userDB.get(superuserUUID);
      })
      .then(function (newUser) {
        verifyEmailToken = newUser.unverifiedEmail.token;
        expect(isUUID(hyphenizeUUID(newUser._id))).to.be.true;
        expect(newUser.key).to.equal('superuser');
        expect(newUser.roles[0]).to.equal('user');
        expect(newUser.local.salt).to.be.a('string');
        expect(newUser.local.derived_key).to.be.a('string');
        expect(newUser.local.created >= now).to.be.true;
        expect(newUser.modelTest).to.equal(true);
        expect(newUser.roles[0]).to.equal('user');
        expect(newUser.activity[0].action).to.equal('signup');
        expect(newUser.onCreate1).to.equal(true);
        expect(newUser.onCreate2).to.equal(true);
        expect(newUser.age).to.equal('32');
        expect(newUser.zipcode).to.equal('ABC123');
        return emitterPromise;
      });
  });

  it('should have created a user db with design doc and _security', function () {
    console.log('Checking user db and design doc');
    userTestDB = couch.db.use('test_usertest$' + superuserUUID);
    return previous
      .then(function () {
        return userTestDB.get('_design/test');
      })
      .then(function (ddoc) {
        expect(ddoc.views.mytest.map).to.be.a('string');
        return userTestDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.admins.roles[secDoc.admins.roles.length - 1]).to.equal(
          'admin_role'
        );
        expect(secDoc.members.roles[secDoc.members.roles.length - 1]).to.equal(
          'member_role'
        );
      });
  });

  it('should authenticate the password', function () {
    console.log('Authenticating password');
    return previous
      .then(function () {
        console.log('Fetching created user');
        return userDB.get(superuserUUID);
      })
      .then(function (newUser) {
        return user.verifyPassword(newUser.local, 'superlogin');
      })
      .then(function (result) {
        console.log('Password authenticated');
      });
  });

  it('should upgrade old local setup (salt, derived_key, created only)', function () {
    let oldUserDoc;
    return previous
      .then(function () {
        // Create a user with old hash format (no iterations, no pbkdf2_prf)
        return user.createUser({
          name: 'Old Hash User',
          username: 'oldhashuser',
          email: 'oldhash@example.com',
          password: 'testpass123',
          confirmPassword: 'testpass123',
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Modify the user doc to simulate old format
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        oldUserDoc = userDoc;
        // Remove new hash properties to simulate old format
        delete oldUserDoc.local.iterations;
        delete oldUserDoc.local.pbkdf2_prf;
        return userDB.insert(oldUserDoc);
      })
      .then(function () {
        return userDB.get(oldUserDoc._id);
      })
      .then(function (userDoc) {
        // Verify old format
        expect(userDoc.local.iterations).to.be.undefined;
        expect(userDoc.local.pbkdf2_prf).to.be.undefined;
        expect(userDoc.local.salt).to.be.a('string');
        expect(userDoc.local.derived_key).to.be.a('string');
        
        // Upgrade the hash
        return user.upgradePasswordHashIfNeeded(userDoc, 'testpass123');
      })
      .then(function () {
        return userDB.get(oldUserDoc._id);
      })
      .then(function (upgradedDoc) {
        // Verify upgrade happened
        expect(upgradedDoc.local.iterations).to.be.a('number');
        expect(upgradedDoc.local.pbkdf2_prf).to.be.a('string');
        expect(upgradedDoc.local.salt).to.be.a('string');
        expect(upgradedDoc.local.derived_key).to.be.a('string');
        
        // Verify password still works
        return user.verifyPassword(upgradedDoc.local, 'testpass123');
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should upgrade local setup with insufficient iterations', function () {
    let lowIterUserDoc;
    return previous
      .then(function () {
        // Create a user with current format but low iterations
        return user.createUser({
          name: 'Low Iter User',
          username: 'lowiteruser',
          email: 'lowiter@example.com',
          password: 'testpass456',
          confirmPassword: 'testpass456',
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        lowIterUserDoc = userDoc;
        // Set low iterations to simulate outdated hash
        lowIterUserDoc.local.iterations = 100; // Much lower than config default
        return userDB.insert(lowIterUserDoc);
      })
      .then(function () {
        return userDB.get(lowIterUserDoc._id);
      })
      .then(function (userDoc) {
        const oldIterations = userDoc.local.iterations;
        expect(oldIterations).to.equal(100);
        
        // Upgrade the hash
        return user.upgradePasswordHashIfNeeded(userDoc, 'testpass456');
      })
      .then(function () {
        return userDB.get(lowIterUserDoc._id);
      })
      .then(function (upgradedDoc) {
        // Verify iterations were increased
        expect(upgradedDoc.local.iterations).to.be.greaterThan(100);
        expect(upgradedDoc.local.pbkdf2_prf).to.be.a('string');
        
        // Verify password still works
        return user.verifyPassword(upgradedDoc.local, 'testpass456');
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should not upgrade current local setup with sufficient security', function () {
    let currentUserDoc;
    let originalHash;
    return previous
      .then(function () {
        // Create a user with current secure format
        return user.createUser({
          name: 'Current User',
          username: 'currentuser',
          email: 'current@example.com',
          password: 'testpass789',
          confirmPassword: 'testpass789',
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        currentUserDoc = userDoc;
        originalHash = {
          salt: userDoc.local.salt,
          derived_key: userDoc.local.derived_key,
          iterations: userDoc.local.iterations,
          pbkdf2_prf: userDoc.local.pbkdf2_prf
        };
        
        // Verify current format has good security parameters
        expect(userDoc.local.iterations).to.be.a('number');
        expect(userDoc.local.iterations).to.be.greaterThan(500); // Should be secure enough
        expect(userDoc.local.pbkdf2_prf).to.be.a('string');
        
        // Try to upgrade (should be no-op)
        return user.upgradePasswordHashIfNeeded(userDoc, 'testpass789');
      })
      .then(function () {
        return userDB.get(currentUserDoc._id);
      })
      .then(function (unchangedDoc) {
        // Verify nothing changed
        expect(unchangedDoc.local.salt).to.equal(originalHash.salt);
        expect(unchangedDoc.local.derived_key).to.equal(originalHash.derived_key);
        expect(unchangedDoc.local.iterations).to.equal(originalHash.iterations);
        expect(unchangedDoc.local.pbkdf2_prf).to.equal(originalHash.pbkdf2_prf);
        
        // Verify password still works
        return user.verifyPassword(unchangedDoc.local, 'testpass789');
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should validate legacy user with old iterations-based hashing', function () {
    let legacyUserDoc;
    const testPassword = 'legacy123';
    const legacyCreatedTime = 1500000000; // Before 1596797642, so should use 10 iterations
    
    return previous
      .then(function () {
        console.log('Creating legacy user...');
        // Create a user to get a proper document structure
        return user.createUser({
          name: 'Legacy User',
          username: 'legacyuser',
          email: 'legacy@example.com',
          password: testPassword,
          confirmPassword: testPassword,
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        legacyUserDoc = userDoc;
        
        // Simulate legacy format by removing new hash properties and setting old created time
        delete legacyUserDoc.local.iterations;
        delete legacyUserDoc.local.pbkdf2_prf;
        legacyUserDoc.local.created = legacyCreatedTime;
        
        // Hash password with legacy method (10 iterations, sha1) to simulate old data
        const legacyPwd = new (require('@sl-nx/couch-pwd'))(10, 20, 16, 'hex', 'sha1');
        return new Promise((resolve, reject) => {
          legacyPwd.hash(testPassword, (err, salt, hash) => {
            if (err) return reject(err);
            legacyUserDoc.local.salt = salt;
            legacyUserDoc.local.derived_key = hash;
            resolve(userDB.insert(legacyUserDoc));
          });
        });
      })
      .then(function (result) {
        return userDB.get(legacyUserDoc._id);
      })
      .then(function (userDoc) {
        console.log('Retrieved updated document successfully');
        // Verify legacy format
        expect(userDoc.local.iterations).to.be.undefined;
        expect(userDoc.local.pbkdf2_prf).to.be.undefined;
        expect(userDoc.local.created).to.equal(legacyCreatedTime);
        expect(userDoc.local.salt).to.be.a('string');
        expect(userDoc.local.derived_key).to.be.a('string');
        
        // Verify legacy password validation works
        return user.verifyPassword(userDoc.local, testPassword);
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should validate legacy user with newer iterations-based hashing', function () {
    let newLegacyUserDoc;
    const testPassword = 'newlegacy456';
    const newLegacyCreatedTime = 1600000000; // After 1596797642, so should use 10000 iterations
    
    return previous
      .then(function () {
        // Create a user to get a proper document structure
        return user.createUser({
          name: 'New Legacy User',
          username: 'newlegacyuser',
          email: 'newlegacy@example.com',
          password: testPassword,
          confirmPassword: testPassword,
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        newLegacyUserDoc = userDoc;
        
        // Simulate newer legacy format by removing new hash properties and setting newer created time
        delete newLegacyUserDoc.local.iterations;
        delete newLegacyUserDoc.local.pbkdf2_prf;
        newLegacyUserDoc.local.created = newLegacyCreatedTime;
        
        // Hash password with newer legacy method (10000 iterations, sha1) to simulate old data
        const newLegacyPwd = new (require('@sl-nx/couch-pwd'))(10000, 20, 16, 'hex', 'sha1');
        return new Promise((resolve, reject) => {
          newLegacyPwd.hash(testPassword, (err, salt, hash) => {
            if (err) return reject(err);
            newLegacyUserDoc.local.salt = salt;
            newLegacyUserDoc.local.derived_key = hash;
            resolve(userDB.insert(newLegacyUserDoc));
          });
        });
      })
      .then(function () {
        return userDB.get(newLegacyUserDoc._id);
      })
      .then(function (userDoc) {
        // Verify legacy format
        expect(userDoc.local.iterations).to.be.undefined;
        expect(userDoc.local.pbkdf2_prf).to.be.undefined;
        expect(userDoc.local.created).to.equal(newLegacyCreatedTime);
        expect(userDoc.local.salt).to.be.a('string');
        expect(userDoc.local.derived_key).to.be.a('string');
        
        // Verify legacy password validation works with higher iterations
        return user.verifyPassword(userDoc.local, testPassword);
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should validate new user with configured userHashing parameters', function () {
    let newHashUserDoc;
    const testPassword = 'newhash789';
    
    return previous
      .then(function () {
        // Create a user which should use the new hashing system with custom config
        return user.createUser({
          name: 'New Hash User',
          username: 'newhashuser',
          email: 'newhash@example.com',
          password: testPassword,
          confirmPassword: testPassword,
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        newHashUserDoc = userDoc;
        
        // Verify new format with custom configuration values
        expect(userDoc.local.iterations).to.equal(50000); // Our custom config value
        expect(userDoc.local.pbkdf2_prf).to.equal('sha256'); // Our custom config value
        expect(userDoc.local.salt).to.be.a('string');
        expect(userDoc.local.derived_key).to.be.a('string');
        expect(userDoc.local.password_scheme).to.equal('pbkdf2');
        
        // Verify new password validation works with custom parameters
        return user.verifyPassword(userDoc.local, testPassword);
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should verify upgrade from legacy to new hashing preserves validation', function () {
    let transitionUserDoc;
    const testPassword = 'transition999';
    const legacyCreatedTime = 1500000000; // Old timestamp for legacy hashing
    
    return previous
      .then(function () {
        // Create a user to get a proper document structure
        return user.createUser({
          name: 'Transition User',
          username: 'transitionuser',
          email: 'transition@example.com',
          password: testPassword,
          confirmPassword: testPassword,
          consents: {
            privacy: { version: 2, accepted: true },
            marketing: { version: 3, accepted: true }
          }
        }, req);
      })
      .then(function (newUser) {
        // Wait briefly to ensure database write has completed
        return timeoutPromise(50).then(() => userDB.get(newUser._id));
      })
      .then(function (userDoc) {
        transitionUserDoc = userDoc;
        
        // Simulate legacy format
        delete transitionUserDoc.local.iterations;
        delete transitionUserDoc.local.pbkdf2_prf;
        transitionUserDoc.local.created = legacyCreatedTime;
        
        // Hash password with legacy method
        const legacyPwd = new (require('@sl-nx/couch-pwd'))(10, 20, 16, 'hex', 'sha1');
        return new Promise((resolve, reject) => {
          legacyPwd.hash(testPassword, (err, salt, hash) => {
            if (err) return reject(err);
            transitionUserDoc.local.salt = salt;
            transitionUserDoc.local.derived_key = hash;
            resolve(userDB.insert(transitionUserDoc));
          });
        });
      })
      .then(function () {
        return userDB.get(transitionUserDoc._id);
      })
      .then(function (userDoc) {
        // Verify legacy validation works
        return user.verifyPassword(userDoc.local, testPassword).then(() => {
          return userDoc;
        });
      })
      .then(function (userDoc) {
        // Now upgrade the hash
        return user.upgradePasswordHashIfNeeded(userDoc, testPassword);
      })
      .then(function () {
        return userDB.get(transitionUserDoc._id);
      })
      .then(function (upgradedDoc) {
        // Verify upgrade happened with custom config values
        expect(upgradedDoc.local.iterations).to.equal(50000); // Our custom config value
        expect(upgradedDoc.local.pbkdf2_prf).to.equal('sha256'); // Our custom config value
        expect(upgradedDoc.local.salt).to.be.a('string');
        expect(upgradedDoc.local.derived_key).to.be.a('string');
        
        // Verify password still works after upgrade
        return user.verifyPassword(upgradedDoc.local, testPassword);
      })
      .then(() => {
        // Reset promise chain for next test
        previous = Promise.resolve();
      });
  });

  it('should generate a validation error trying to save the same user again', function () {
    return previous
      .then(function () {
        console.log('Trying to create the user again');
        return user.createUser(testUserForm);
      })
      .then(function () {
        throw new Error('Validation errors should have been generated');
      })
      .catch(function (err) {
        if (err.validationErrors) {
          expect(err.validationErrors.email[0]).to.equal(
            'Email already in use'
          );
          expect(err.validationErrors.username[0]).to.equal(
            'Username already in use'
          );
        } else {
          throw err;
        }
      });
  });

  it('should send an email if registering with same email', () => {
    spySendMail = sinon.spy(mailer, 'sendEmail');
    const emitterPromise = new Promise<void>(resolve => {
      emitter.once('signup-attempt', () => {
        console.log('emitter: got attempt.');
        resolve();
      });
    });

    return previous
      .then(() => {
        userConfig.local.requireEmailConfirm = true;
        userConfig.local.emailUsername = true;
        const newForm = { ...testUserForm };
        newForm.username = 'superuser2';
        return Promise.all([user.createUser(newForm), emitterPromise]);
      })
      .then(res => {
        userConfig.local.requireEmailConfirm = false;
        userConfig.local.emailUsername = false;
        expect(res[0]).to.equal(undefined);
        expect(spySendMail.callCount).to.equal(1);
        return Promise.resolve();
      });
  });

  let sessionKey, sessionPass, firstExpires;

  it('should generate a new session for the user', function () {
    const emitterPromise = new Promise<void>(resolve => {
      emitter.once('login', session => {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(() => {
        console.log('Creating session');
        return user.createSession({
          login: testUserForm.username,
          provider: 'local'
        });
      })
      .then(result => {
        sessionKey = result.token;
        sessionPass = result.password;
        firstExpires = result.expires;
        expect(sessionKey).to.be.a('string');
        expect(result.userDBs.usertest).to.equal(
          'https://' +
            sessionKey +
            ':' +
            sessionPass +
            '@' +
            'mydb.example.com/test_usertest$' +
            superuserUUID
        );
        return userDB.get(superuserUUID);
      })
      .then(function (user) {
        expect(user.activity[0].action).to.equal('login');
        return emitterPromise;
      });
  });

  it('should have authorized the session in the usertest database', function () {
    return previous
      .then(function () {
        console.log('Verifying session is authorized in personal db');
        return userTestDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(1);
      });
  });

  it('should refresh a session', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('refresh', function (session) {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Refreshing session for key: ', sessionKey);
        return user.refreshSession(sessionKey);
      })
      .then(function (result) {
        expect(result.expires).to.be.above(firstExpires);
        return emitterPromise;
      });
  });

  it('should confirm a session', function (done) {
    previous
      .then(() => {
        return user.confirmSession(sessionKey, sessionPass);
      })
      .then(token => {
        expect(token.key).to.equal(sessionKey);
        expect(token.provider).to.equal('local');
        expect(token.roles).to.include('user');
        expect(token.roles).to.include('user:superuser');
        expect(token._id).to.equal('superuser');
        for (const k of ['password', 'salt', 'iterations', 'password_scheme']) {
          expect(token[k]).to.equal(undefined);
        }
        console.log('confirmed with db fallback');
        done();
      })
      .catch(err => done(err));
  });

  it('should log out of a session', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('logout', function (user_id) {
        expect(user_id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Logging out of the session');
        return user.logoutSession(sessionKey);
      })
      .then(function () {
        return user.confirmSession(sessionKey, sessionPass);
      })
      .then(
        function () {
          throw new Error('Failed to log out of session');
        },
        function (err) {
          expect(err.message).to.equal('invalid token');
          return userDB.get(superuserUUID);
        }
      )
      .then(function (user) {
        expect(user.session[sessionKey]).to.be.an('undefined');
        expect(user.inactiveSessions.length).to.equal(1);
        return emitterPromise;
      });
  });

  it('should have deauthorized the session in the usertest database after logout', function () {
    return previous
      .then(function () {
        return userTestDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
      });
  });

  it('should log the user out of all sessions', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('logout-all', function (user_id) {
        expect(user_id).to.equal('superuser');
        resolve();
      });
    });

    const sessions = [];
    const passes = [];

    return previous
      .then(function () {
        console.log('Logging user out completely');
        return user.createSession({
          login: testUserForm.username,
          provider: 'local'
        });
      })
      .then(function (session1) {
        sessions[0] = session1.token;
        passes[0] = session1.password;
        return user.createSession({
          login: testUserForm.username,
          provider: 'local'
        });
      })
      .then(function (session2) {
        sessions[1] = session2.token;
        passes[1] = session2.password;
        return user.logoutAll(null, sessions[0]);
      })
      .then(function () {
        return Promise.all([
          user.confirmSession(sessions[0], passes[0]),
          user.confirmSession(sessions[1], passes[1])
        ]);
      })
      .then(
        function (results) {
          throw new Error('Failed to delete user sessions');
        },
        function (error) {
          expect(error.message).to.equal('invalid token');
          return userDB.get(superuserUUID);
        }
      )
      .then(function (user) {
        expect(user.session).to.be.an('undefined');
        expect(user.inactiveSessions.length).to.equal(2);
        // Make sure the sessions are deauthorized in the usertest db
        return userTestDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
        return emitterPromise;
      });
  });

  it('should verify the email', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('email-verified', function (user) {
        expect(user.key).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Verifying email with token');
        return user.verifyEmail(verifyEmailToken);
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(function (verifiedUser) {
        expect(verifiedUser.email).to.equal(testUserForm.email);
        expect(verifiedUser.activity[0].action).to.equal('email-verified');
        expect(verifiedUser.lastEmailToken).to.equal(verifyEmailToken);
        return emitterPromise;
      });
  });

  it('should generate a password reset token', function () {
    const emitterPromise = new Promise<any>(function (resolve) {
      emitter.once('forgot-password', function ({ user, token }) {
        expect(user.key).to.equal('superuser');
        resolve(user);
      });
    });

    return previous
      .then(() =>
        Promise.all([
          user
            .forgotPassword(testUserForm.email, req)
            .then(() => userDB.get(superuserUUID)),
          emitterPromise
        ])
      )
      .then(results => {
        const result = results[1];
        expect(results[0]._id).to.equal(results[1]._id);
        resetTokenHashed = result.forgotPassword.token; // hashed token stored in db

        expect(result.forgotPassword.token).to.be.a('string');
        expect(result.forgotPassword.expires).to.be.above(Date.now());
        expect(result.activity[0].action).to.equal('forgot-password');

        expect(spySendMail.callCount).to.equal(2);
        const args = spySendMail.getCall(1).args;
        expect(args[0]).to.equal('forgotPassword');
        expect(args[1]).to.equal(testUserForm.email);
        console.log('got args user._id');
        expect(args[2].user.key).to.equal(testUserForm.username);
        expect(args[2].token).to.be.a('string');

        resetToken = args[2].token; // keep unhashed token emailed to user.
        expect(resetTokenHashed).to.not.equal(resetToken);
      });
  });

  it('should not reset the password', function () {
    new Promise<void>(function (resolve) {
      emitter.once('email-changed', function (user) {
        expect(user.key).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Resetting the password');
        const form = {
          token: resetToken,
          password: 'secret',
          confirmPassword: 'secret'
        };
        return user.resetPassword(form);
      })
      .then(function () {
        throw new Error('Validation errors should have been generated');
      })
      .catch(function (err) {
        if (err.validationErrors) {
          expect(err.validationErrors.password[0]).to.equal(
            'Password must be at least 8 characters'
          );
        } else {
          throw err;
        }
      });
  });

  it('should reset the password', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('password-reset', function (user) {
        expect(user.key).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Resetting the password');
        const form = {
          token: resetToken,
          password: 'newSecret',
          confirmPassword: 'newSecret'
        };
        return user.resetPassword(form);
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(function (userAfterReset) {
        // It should delete the password reset token completely
        expect(userAfterReset.forgotPassword).to.be.undefined;
        expect(userAfterReset.activity[0].action).to.equal('password-reset');

        expect(spySendMail.callCount).to.equal(3);
        const args = spySendMail.getCall(2).args;
        expect(args[0]).to.equal('modifiedPassword');
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user._id).to.equal(superuserUUID);
        expect(args[2].user.key).to.equal(testUserForm.username);

        return user.verifyPassword(userAfterReset.local, 'newSecret');
      })
      .then(function () {
        return emitterPromise;
      });
  });

  it('should change the password', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('password-change', function (user) {
        expect(user.key).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Changing the password');
        const form = {
          currentPassword: 'newSecret',
          newPassword: 'superpassword2',
          confirmPassword: 'superpassword2'
        };
        return user.changePasswordSecure(testUserForm.username, form);
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(function (userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal('password-change');

        expect(spySendMail.callCount).to.equal(4);
        const args = spySendMail.getCall(3).args;
        expect(args[0]).to.equal('modifiedPassword');
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user.key).to.equal(testUserForm.username);
        expect(args[2].user._id).to.equal(superuserUUID);

        return user.verifyPassword(userAfterChange.local, 'superpassword2');
      })
      .then(function () {
        return emitterPromise;
      });
  });

  it('should request to change the email', function () {
    const emitterPromise = new Promise<any>(resolve => {
      emitter.once('email-changed', user => {
        expect(user.key).to.equal('superuser');
        resolve(user);
      });
    });

    return previous
      .then(() => {
        console.log('Changing the email');
        return user.changeEmail(
          testUserForm.username,
          'Superuser2@example.com ',
          req
        );
      })
      .then(() => emitterPromise)
      .then(() => userDB.get(superuserUUID))
      .then(userAfterChange => {
        expect(userAfterChange.activity[0].action).to.equal('email-changed');
        expect(userAfterChange.unverifiedEmail.email).to.equal(
          'superuser2@example.com'
        );
        expect(userAfterChange.lastEmailToken).to.be.undefined;
        return Promise.resolve();
      });
  });

  it('should create a new account from facebook auth', function () {
    const emitterPromise = new Promise<void>(function (resolve) {
      emitter.once('signup', function (user) {
        expect(user.email).to.equal('misterx@example.com');
        resolve();
      });
    });

    const auth = { token: 'x' };
    const profile = {
      id: 'abc123',
      username: 'misterx',
      emails: [{ value: 'misterx@example.com' }]
    };

    return previous
      .then(() => {
        console.log('Authenticating new facebook user');
        return user.createUserSocial('facebook', auth, profile);
      })
      .then(newUser => {
        misterxUUID = newUser._id;
        return userDB.get(misterxUUID);
      })
      .then(result => {
        expect(result.facebook.auth.token).to.equal('x');
        expect(result.email).to.equal('misterx@example.com');
        expect(result.providers[0]).to.equal('facebook');
        expect(result.facebook.profile.username).to.equal('misterx');
        expect(result.activity[0].action).to.equal('signup');
        expect(result.activity[0].provider).to.equal('facebook');

        misterxKey = result.key;
        return emitterPromise;
      });
  });

  it('should refresh an existing account from facebook auth', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'abc123',
      username: misterxKey,
      emails: [{ value: 'misterx@example.com' }]
    };

    return previous
      .then(function () {
        console.log('Authenticating existing facebook user');
        return user.createUserSocial('facebook', auth, profile);
      })
      .then(function () {
        return userDB.get(misterxUUID);
      })
      .then(function (result) {
        expect(result.facebook.auth.token).to.equal('y');
      });
  });

  it('should reject an email already in use', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'cde456',
      username: 'misterx2',
      emails: [{ value: 'misterx@example.com' }]
    };

    return previous
      .then(function () {
        console.log('Making sure an existing email is rejected');
        return user.createUserSocial('facebook', auth, profile);
      })
      .then(
        function () {
          throw new Error('existing email should have been rejected');
        },
        function (err) {
          expect(err.status).to.equal(409);
        }
      );
  });

  /*
  it('should generate a username in case of conflict', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'cde456',
      username: 'misterx',
      emails: [{ value: 'misterx99@example.com' }]
    };
    const docs = [
      { _id: uuidv4(), key: 'misterx1' },
      { _id: uuidv4(), key: 'misterx2' },
      { _id: uuidv4(), key: 'misterx4' }
    ];

    return previous
      .then(function () {
        return userDB.bulk({ docs: docs });
      })
      .then(function () {
        return user.socialAuth('facebook', auth, profile);
      })
      .then(function (result) {
        createdDBs.push('test_usertest$' + result._id);
        expect(result.email).to.equal('misterx99@example.com');
      });
  });
  */

  it('should link a social profile to an existing user', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'efg789',
      username: 'superuser',
      emails: [{ value: 'superuser@example.com' }]
    };

    return previous
      .then(function () {
        console.log('Linking social profile to existing user');
        return user.linkUserSocial('superuser', 'facebook', auth, profile);
      })
      .then(function (theUser) {
        expect(theUser.facebook.profile.username).to.equal('superuser');
        expect(theUser.activity[0].action).to.equal('link-social');
        expect(theUser.activity[0].provider).to.equal('facebook');
        // Test that the activity list is limited to the maximum value
        expect(theUser.activity.length).to.equal(3);
      });
  });

  it('should unlink a social profile', function () {
    return previous
      .then(function () {
        console.log('Unlinking a social profile');
        return user.unlinkUserSocial('superuser', 'facebook');
      })
      .then(function (theUser) {
        expect(typeof theUser.facebook).to.equal('undefined');
        expect(theUser.providers.length).to.equal(1);
        expect(theUser.providers.indexOf('facebook')).to.equal(-1);
      });
  });

  it('should clean all expired sessions', function () {
    const now = Date.now();
    testUserUUID = uuidv4();
    const testUser = {
      _id: testUserUUID,
      key: 'testuser',
      session: {
        good1: {
          expires: now + 100000
        },
        bad1: {
          expires: now - 100000
        },
        bad2: {
          expires: now - 100000
        }
      }
    };

    return previous
      .then(function () {
        console.log('Cleaning expired sessions');
        // @ts-ignore
        return user.dbAuth.logoutUserSessions(testUser, 'expired');
      })
      .then(function (finalDoc) {
        expect(Object.keys(finalDoc.session).length).to.equal(1);
        expect(finalDoc.session).to.include.keys('good1');
      });
  });

  it('should log out of all other sessions', function () {
    const testUser = {
      _id: testUserUUID,
      key: 'testuser',
      session: {
        this1: {},
        other1: {},
        other2: {}
      }
    };

    return previous
      .then(function () {
        console.log('Logging out of other sessions');
        // @ts-ignore
        return userDB.insert(testUser);
      })
      .then(function () {
        return user.logoutOthers('this1');
      })
      .then(function () {
        return userDB.get(testUserUUID);
      })
      .then(function (finalDoc) {
        expect(Object.keys(finalDoc.session).length).to.equal(1);
        expect(finalDoc.session).to.include.keys('this1');
      });
  });

  it('should add a new user database', function () {
    return previous
      .then(function () {
        console.log('Adding a new user database');
        return user.addUserDB('superuser', 'test_superdb', 'shared');
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(function (userDoc) {
        expect(userDoc.personalDBs.test_superdb.type).to.equal('shared');
        return checkDBExists('test_superdb');
      })
      .then(function (result) {
        expect(result).to.equal(true);
      });
  });

  it('should remove a user database', function () {
    return previous
      .then(function () {
        console.log('Removing a user database');
        return user.removeUserDB('superuser', 'test_superdb', false, true);
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(function (userDoc) {
        expect(typeof userDoc.personalDBs.test_superdb).to.equal('undefined');
        return checkDBExists('test_superdb');
      })
      .then(function (result) {
        expect(result).to.equal(false);
      });
  });

  it('should delete a user and all databases', function () {
    return previous
      .then(function () {
        console.log('Deleting user');
        return checkDBExists('test_usertest$' + superuserUUID);
      })
      .then(function (result) {
        expect(result).to.equal(true);
        return user.removeUser('superuser', true);
      })
      .then(function () {
        return userDB.get(superuserUUID);
      })
      .then(
        function (result) {
          throw 'User should have been deleted!';
        },
        function (err) {
          expect(err.error).to.equal('not_found');
          expect(err.statusCode).to.equal(404);
          return checkDBExists('test_usertest$' + superuserUUID);
        }
      )
      .then(function (result) {
        expect(result).to.equal(false);
      });
  });

  it('should create a new user in userEmail mode', function () {
    return previous
      .then(() => {
        userConfig.local.emailUsername = true;
        // Don't create any more userDBs
        delete userConfig.userDBs.defaultDBs;
        // Create a new instance of user with the new config
        user = new User(userConfig, userDB, keysDB, mailer, emitter, couch);
        return user.createUser(emailUserForm, req);
      })
      .then(newUser => {
        //userEmailUUID = newUser._id;
        //createdDBs.push('test_usertest$' + userEmailUUID);
        expect(newUser.unverifiedEmail.email).to.equal(emailUserForm.email);
        expect(newUser.key).to.exist;
        return timeoutPromise(500);
      });
  });

  it('should not create a user with conflicting email', function () {
    return previous
      .then(function () {
        return user.createUser(emailUserForm, req);
      })
      .then(
        function () {
          throw 'Should not have created the user!';
        },
        function (err) {
          if (err.error) {
            expect(err.error).to.equal('Validation failed');
          } else {
            throw err;
          }
        }
      );
  });

  function checkDBExists(dbname) {
    const finalUrl = dbUrl + '/' + dbname;
    return request
      .get(finalUrl)
      .then(res => {
        const result = JSON.parse(res.text);
        if (result.db_name) {
          return Promise.resolve(true);
        }
      })
      .catch(err => {
        if (err.status === 404) {
          return Promise.resolve(false);
        }
      });
  }
});
