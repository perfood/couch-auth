'use strict';
const events = require('events');
const path = require('path');
const Configure = require('../lib/config/configure').ConfigHelper;
const User = require('../lib/user').User;
const Mailer = require('../lib/mailer').Mailer;
const util = require('../lib/util');
const seed = require('../lib/design/seed').default;
const request = require('superagent');
const config = require('./test.config.js');
const nano = require('nano');

const chai = require('chai');
const sinon = require('sinon');
const expect = chai.expect;
chai.use(require('sinon-chai'));

const dbUrl = util.getDBURL(config.dbServer);
const couch = nano({ url: dbUrl, parseUrl: false });

const emitter = new events.EventEmitter();

const userDB = couch.db.use('superlogin_test_users');
const keysDB = couch.db.use('superlogin_test_keys');

const testUserForm = {
  name: 'Super',
  username: 'superuser',
  email: 'superuser@example.com',
  password: 'superlogin',
  confirmPassword: 'superlogin',
  age: '32',
  zipcode: 'ABC123'
};

const emailUserForm = {
  name: 'Awesome',
  email: 'awesome@example.com',
  password: 'supercool',
  confirmPassword: 'supercool'
};

const userConfig = new Configure({
  testMode: {
    noEmail: true
  },
  security: {
    defaultRoles: ['user'],
    userActivityLogSize: 3
  },
  local: {
    sendConfirmEmail: true,
    requireEmailConfirm: false,
    sendPasswordChangedEmail: true,
    passwordConstraints: {
      length: {
        minimum: 8,
        message: 'must be at least 8 characters'
      },
      matches: 'confirmPassword'
    }
  },
  mailer: {
    fromEmail: 'noreply@example.com'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../templates/email/confirm-email.ejs'),
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: path.join(__dirname, '../templates/email/forgot-password.ejs'),
      format: 'text'
    },
    modifiedPassword: {
      subject: 'Your password has been modified',
      template: path.join(
        __dirname,
        '../templates/email/modified-password.ejs'
      ),
      format: 'text'
    }
  },
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password,
    publicURL: 'https://mydb.example.com'
  },
  session: {
    adapter: 'memory',
    dbFallback: true
  },
  userDBs: {
    defaultSecurityRoles: {
      admins: ['admin_role'],
      members: ['member_role']
    },
    model: {
      _default: {
        designDocs: ['test'],
        permissions: ['_reader', '_writer', '_replicator']
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

const req = {
  headers: {
    host: 'example.com'
  },
  protocol: 'http',
  ip: '1.1.1.1'
};

describe('User Model', async function () {
  const mailer = new Mailer(userConfig);
  let user = new User(userConfig, userDB, keysDB, mailer, emitter);
  let userTestDB;
  let previous;
  let verifyEmailToken;

  before(async function () {
    await couch.db.create('superlogin_test_users');
    await couch.db.create('superlogin_test_keys');
    let userDesign = require('../lib/design/user-design');
    userDesign = util.addProvidersToDesignDoc(userConfig, userDesign);
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
      const testDbs = [
        'superlogin_test_users',
        'superlogin_test_keys',
        'test_usertest$superuser',
        'test_usertest$misterx',
        'test_usertest$misterx3',
        'test_superdb'
      ];
      for (const testDb of testDbs) {
        try {
          await couch.db.destroy(testDb);
        } catch (err) {
          if (!['test_superdb', 'test_usertest$superuser'].includes(testDb)) {
            console.log('Expected but could not delete db: ', testDb);
          }
        }
      }
      return Promise.resolve();
      //return Promise.(testDbs.map(db => couch.db.destroy(db)));
    });
  });

  it('should save a new user', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('signup', function (user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        user.onCreate(userDoc => {
          userDoc.onCreate1 = true;
          return Promise.resolve(userDoc);
        });
        user.onCreate(userDoc => {
          userDoc.onCreate2 = true;
          return Promise.resolve(userDoc);
        });
        return user.createUser(testUserForm, req);
      })
      .then(function () {
        console.log('User created');
        return userDB.get(testUserForm.username);
      })
      .then(function (newUser) {
        verifyEmailToken = newUser.unverifiedEmail.token;
        expect(newUser._id).to.equal('superuser');
        expect(newUser.roles[0]).to.equal('user');
        expect(newUser.local.salt).to.be.a('string');
        expect(newUser.local.derived_key).to.be.a('string');
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
    userTestDB = couch.db.use('test_usertest$superuser');
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
        return userDB.get(testUserForm.username);
      })
      .then(function (newUser) {
        return util.verifyPassword(newUser.local, 'superlogin');
      })
      .then(function (result) {
        console.log('Password authenticated');
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

  let sessionKey, sessionPass, firstExpires;

  it('should generate a new session for the user', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('login', function (session) {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Creating session');
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function (result) {
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
            'mydb.example.com/test_usertest$superuser'
        );
        return userDB.get(testUserForm.username);
      })
      .then(function (user) {
        expect(user.session[sessionKey].ip).to.equal('1.1.1.1');
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
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('refresh', function (session) {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Refreshing session');
        return user.refreshSession(sessionKey);
      })
      .then(function (result) {
        expect(result.expires).to.be.above(firstExpires);
        return emitterPromise;
      });
  });

  it('should restore a valid session', function (done) {
    previous
      .then(() => {
        return user.removeFromSessionCache(sessionKey);
      })
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
      });
  });

  it('should log out of a session', function () {
    const emitterPromise = new Promise(function (resolve) {
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
          expect(err).to.equal('invalid token');
          return userDB.get(testUserForm.username);
        }
      )
      .then(function (user) {
        expect(user.session[sessionKey]).to.be.an('undefined');
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
    const emitterPromise = new Promise(function (resolve) {
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
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function (session1) {
        sessions[0] = session1.token;
        passes[0] = session1.password;
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function (session2) {
        sessions[1] = session2.token;
        passes[1] = session2.password;
        return user.logoutUser(null, sessions[0]);
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
          expect(error).to.equal('invalid token');
          return userDB.get(testUserForm.username);
        }
      )
      .then(function (user) {
        expect(user.session).to.be.an('undefined');
        // Make sure the sessions are deauthorized in the usertest db
        return userTestDB.get('_security');
      })
      .then(function (secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
        return emitterPromise;
      });
  });

  it('should verify the email', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('email-verified', function (user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Verifying email with token');
        return user.verifyEmail(verifyEmailToken);
      })
      .then(function () {
        return userDB.get(testUserForm.username);
      })
      .then(function (verifiedUser) {
        expect(verifiedUser.email).to.equal(testUserForm.email);
        expect(verifiedUser.activity[0].action).to.equal('verified email');
        return emitterPromise;
      });
  });

  let resetToken;
  let resetTokenHashed;
  let spySendMail;

  it('should generate a password reset token', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('forgot-password', function (user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    spySendMail = sinon.spy(mailer, 'sendEmail');

    return previous
      .then(function () {
        console.log('Generating password reset token');
        return user.forgotPassword(testUserForm.email, req);
      })
      .then(function () {
        return userDB.get(testUserForm.username);
      })
      .then(function (result) {
        resetTokenHashed = result.forgotPassword.token; // hashed token stored in db

        expect(result.forgotPassword.token).to.be.a('string');
        expect(result.forgotPassword.expires).to.be.above(Date.now());
        expect(result.activity[0].action).to.equal('forgot password');

        expect(spySendMail.callCount).to.equal(1);

        const args = spySendMail.getCall(0).args;
        expect(args[0]).to.equal('forgotPassword');
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user._id).to.equal(testUserForm.username);
        expect(args[2].token).to.be.a('string');

        resetToken = args[2].token; // keep unhashed token emailed to user.
        expect(resetTokenHashed).to.not.equal(resetToken);
        return emitterPromise;
      });
  });

  it('should not reset the password', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('email-changed', function (user) {
        expect(user._id).to.equal('superuser');
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
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('password-reset', function (user) {
        expect(user._id).to.equal('superuser');
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
        return userDB.get(testUserForm.username);
      })
      .then(function (userAfterReset) {
        // It should delete the password reset token completely
        expect(userAfterReset.forgotPassword).to.be.an.undefined;
        expect(userAfterReset.activity[0].action).to.equal('reset password');

        expect(spySendMail.callCount).to.equal(2);
        const args = spySendMail.getCall(1).args;
        expect(args[0]).to.equal('modifiedPassword');
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user._id).to.equal(testUserForm.username);

        return util.verifyPassword(userAfterReset.local, 'newSecret');
      })
      .then(function () {
        return emitterPromise;
      });
  });

  it('should change the password', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('password-change', function (user) {
        expect(user._id).to.equal('superuser');
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
        return userDB.get(testUserForm.username);
      })
      .then(function (userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal('changed password');

        expect(spySendMail.callCount).to.equal(3);
        const args = spySendMail.getCall(2).args;
        expect(args[0]).to.equal('modifiedPassword');
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user._id).to.equal(testUserForm.username);

        return util.verifyPassword(userAfterChange.local, 'superpassword2');
      })
      .then(function () {
        return emitterPromise;
      });
  });

  it('should change the email', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('email-changed', function (user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    return previous
      .then(function () {
        console.log('Changing the email');
        return user.changeEmail(
          testUserForm.username,
          'superuser2@example.com',
          req
        );
      })
      .then(function () {
        return userDB.get(testUserForm.username);
      })
      .then(function (userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal('changed email');
        expect(userAfterChange.unverifiedEmail.email).to.equal(
          'superuser2@example.com'
        );
        return emitterPromise;
      });
  });

  it('should create a new account from facebook auth', function () {
    const emitterPromise = new Promise(function (resolve) {
      emitter.once('signup', function (user) {
        expect(user._id).to.equal('misterx');
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
      .then(function () {
        console.log('Authenticating new facebook user');
        return user.socialAuth('facebook', auth, profile, req);
      })
      .then(function () {
        return userDB.get('misterx');
      })
      .then(function (result) {
        expect(result.facebook.auth.token).to.equal('x');
        expect(result.email).to.equal('misterx@example.com');
        expect(result.providers[0]).to.equal('facebook');
        expect(result.facebook.profile.username).to.equal('misterx');
        expect(result.activity[0].action).to.equal('signup');
        expect(result.activity[0].provider).to.equal('facebook');
        return emitterPromise;
      });
  });

  it('should refresh an existing account from facebook auth', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'abc123',
      username: 'misterx',
      emails: [{ value: 'misterx@example.com' }]
    };

    return previous
      .then(function () {
        console.log('Authenticating existing facebook user');
        return user.socialAuth('facebook', auth, profile, req);
      })
      .then(function () {
        return userDB.get('misterx');
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
        return user.socialAuth('facebook', auth, profile, req);
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

  it('should generate a username in case of conflict', function () {
    const auth = { token: 'y' };
    const profile = {
      id: 'cde456',
      username: 'misterx',
      emails: [{ value: 'misterx99@example.com' }]
    };
    const docs = [
      { _id: 'misterx1' },
      { _id: 'misterx2' },
      { _id: 'misterx4' }
    ];

    return previous
      .then(function () {
        return userDB.bulk({ docs: docs });
      })
      .then(function () {
        return user.socialAuth('facebook', auth, profile, req);
      })
      .then(function (result) {
        expect(result._id).to.equal('misterx3');
      });
  });

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
        return user.linkSocial('superuser', 'facebook', auth, profile, {});
      })
      .then(function (theUser) {
        expect(theUser.facebook.profile.username).to.equal('superuser');
        expect(theUser.activity[0].action).to.equal('link');
        expect(theUser.activity[0].provider).to.equal('facebook');
        // Test that the activity list is limited to the maximum value
        expect(theUser.activity.length).to.equal(3);
      });
  });

  it('should unlink a social profile', function () {
    return previous
      .then(function () {
        console.log('Unlinking a social profile');
        return user.unlink('superuser', 'facebook');
      })
      .then(function (theUser) {
        expect(typeof theUser.facebook).to.equal('undefined');
        expect(theUser.providers.length).to.equal(1);
        expect(theUser.providers.indexOf('facebook')).to.equal(-1);
      });
  });

  it('should clean all expired sessions', function () {
    const now = Date.now();
    const testUser = {
      _id: 'testuser',
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
        return user.logoutUserSessions(testUser, 'expired');
      })
      .then(function (finalDoc) {
        expect(Object.keys(finalDoc.session).length).to.equal(1);
        expect(finalDoc.session).to.include.keys('good1');
      });
  });

  it('should log out of all other sessions', function () {
    const testUser = {
      _id: 'testuser',
      session: {
        this1: {},
        other1: {},
        other2: {}
      }
    };

    return previous
      .then(function () {
        console.log('Logging out of other sessions');
        return userDB.insert(testUser);
      })
      .then(function () {
        return user.logoutOthers('this1');
      })
      .then(function () {
        return userDB.get('testuser');
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
        return userDB.get('superuser');
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
        return userDB.get('superuser');
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
        return checkDBExists('test_usertest$superuser');
      })
      .then(function (result) {
        expect(result).to.equal(true);
        return user.removeUser('superuser', true);
      })
      .then(function () {
        return userDB.get('superuser');
      })
      .then(
        function (result) {
          throw 'User should have been deleted!';
        },
        function (err) {
          expect(err.error).to.equal('not_found');
          expect(err.statusCode).to.equal(404);
          return checkDBExists('test_usertest$superuser');
        }
      )
      .then(function (result) {
        expect(result).to.equal(false);
      });
  });

  it('should create a new user in userEmail mode', function () {
    return previous
      .then(function () {
        userConfig.setItem('local.emailUsername', true);
        // Don't create any more userDBs
        userConfig.removeItem('userDBs.defaultDBs');
        // Create a new instance of user with the new config
        user = new User(userConfig, userDB, keysDB, mailer, emitter);
        return user.createUser(emailUserForm, req);
      })
      .then(function (newUser) {
        expect(newUser.unverifiedEmail.email).to.equal(emailUserForm.email);
        expect(newUser._id).to.equal(emailUserForm.email);
      });
  });

  it('should not create a user with conflicting email', function () {
    return previous
      .then(function () {
        return user.createUser(emailUserForm, req);
      })
      .then(
        function (newUser) {
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
