import chai, { expect } from 'chai';
import nano from 'nano';
import sinon from 'sinon';
import request from 'superagent';
import seed from '../lib/design/seed';
import { getDBURL, timeoutPromise } from '../lib/util';
import { config } from './test.config';
chai.use(require('sinon-chai'));

describe('SuperLogin', function () {
  let app;
  /** @type {import('nano').DocumentScope} */
  let userDB;
  /** @type {import('nano').DocumentScope} */
  let keysDB;
  let previous: Promise<any>;
  let accessToken;
  let accessPass;
  let expireCompare;
  let resetToken = null;
  let emailToken;

  const server = 'http://localhost:5000';
  const dbUrl = getDBURL(config.dbServer);
  const couch = nano({ url: dbUrl, parseUrl: false });
  const consents = {
    privacy: {
      version: 3,
      accepted: true
    },
    marketing: {
      version: 2,
      accepted: false
    }
  };

  const newUser = {
    name: 'Kewl Uzer',
    username: 'kewluzer',
    email: 'kewluzer@example.com',
    password: '123s3cret',
    confirmPassword: '123s3cret',
    consents
  };
  const invalidNewUser = { ...newUser, email: 'blah@example' };

  const emptyNewUser = {
    name: '',
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    consents: ''
  };

  const newUser2 = {
    name: 'Kewler Uzer',
    username: 'kewleruzer',
    email: 'kewleruzer@example.com',
    password: '123s3cret',
    confirmPassword: '123s3cret',
    consents
  };
  let newUser2Bearer;

  const findUser = key =>
    userDB
      .find({
        selector: {
          key
        },
        fields: ['unverifiedEmail']
      })
      .then(record => record.docs[0]);

  before(async () => {
    await couch.db.create('sl_test-users');
    await couch.db.create('sl_test-keys');
    userDB = couch.use('sl_test-users');
    keysDB = couch.use('sl_test-keys');
    app = require('./test-server')(config);
    app.superlogin.onCreate((userDoc, provider) => {
      userDoc.profile = { name: userDoc.name };
      return Promise.resolve(userDoc);
    });
    await seed(userDB, require('../lib/design/user-design.js'));
    previous = Promise.resolve();
    return previous;
  });

  after(async () => {
    if (previous) {
      await previous;
    }
    await Promise.all([
      couch.db.destroy('sl_test-users'),
      couch.db.destroy('sl_test-keys')
    ]);
    console.log('DBs Destroyed');
    app.shutdown();
  });

  it('should reject a new user with an invalid email', () => {
    return previous.then(() => {
      return request
        .post(server + '/auth/register')
        .send(invalidNewUser)
        .then(() => {
          return Promise.reject('invalid email should have been rejected');
        })
        .catch(err => {
          expect(err.status).to.equal(400);
          console.log('Rejected user with invalid email');
        });
    });
  });

  it('should reject a new user without matching passwords', () => {
    return previous.then(() => {
      return request
        .post(server + '/auth/register')
        .send({ ...newUser, confirmPassword: 'something else' })
        .then(() => {
          return Promise.reject(
            'different confirmPassword should have been rejected'
          );
        })
        .catch(err => {
          expect(err.status).to.equal(400);
          console.log('Rejected user with different confirmPassword');
        });
    });
  });

  it('should reject a new user with a too short password', () => {
    return previous.then(() => {
      return request
        .post(server + '/auth/register')
        .send({ ...newUser, password: 'abc', confirmPassword: 'abc' })
        .then(() => {
          return Promise.reject('too short password should have been rejected');
        })
        .catch(err => {
          expect(err.status).to.equal(400);
          console.log('Rejected user with too short password');
        });
    });
  });

  it('should reject a new user without any data', () => {
    return previous.then(() => {
      return request
        .post(server + '/auth/register')
        .send(emptyNewUser)
        .then(() => {
          return Promise.reject('empty user should have been rejected');
        })
        .catch(err => {
          expect(err.response.clientError).to.be.true;
          expect(err.response.serverError).to.be.false;
          expect(err.response.body.validationErrors).to.exist;
          expect(
            Object.keys(err.response.body.validationErrors)
          ).length.to.be.greaterThan(1);
          expect(err.status).to.equal(400);
          console.log('Rejected empty user');
        });
    });
  });

  it('should create a new user', function () {
    return previous.then(() => {
      return request
        .post(server + '/auth/register')
        .send(newUser)
        .then(res => {
          expect(res.status).to.equal(200);
          expect(res.body.success).to.equal('Request processed.');
          console.log('User created');
          return timeoutPromise(500);
        });
    });
  });

  it('should verify the email', function () {
    return previous.then(function () {
      return findUser('kewluzer')
        .then(function (record) {
          emailToken = record.unverifiedEmail.token;
          return 1;
        })
        .then(function () {
          return request
            .get(server + '/auth/confirm-email/' + emailToken)
            .then(res => {
              expect(res.status).to.equal(200);
              console.log('Email successfully verified.');
              return Promise.resolve();
            });
        });
    });
  });

  it('should also accept the confirm-email token on the 2nd attempt', () => {
    return previous.then(() => {
      request.get(server + '/auth/confirm-email/' + emailToken).then(res => {
        expect(res.status).to.equal(200);
        console.log('Email successfully verified.');
        return Promise.resolve();
      });
    });
  });

  it('should login the user', function () {
    return previous.then(function () {
      return request
        .post(server + '/auth/login')
        .send({ username: newUser.username, password: newUser.password })
        .then(res => {
          accessToken = res.body.token;
          accessPass = res.body.password;
          expect(res.status).to.equal(200);
          expect(res.body.roles[0]).to.equal('user');
          expect(res.body.token.length).to.be.above(10);
          expect(res.body.profile.name).to.equal(newUser.name);
          console.log('User successfully logged in');
          return Promise.resolve();
        });
    });
  });

  it('should access a protected endpoint', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .get(server + '/auth/session')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .then(res => {
            expect(res.status).to.equal(200);
            console.log('Secure endpoint successfully accessed.');
            resolve();
          });
      });
    });
  });

  it('should require a role', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .get(server + '/user')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .then(res => {
            expect(res.status).to.equal(200);
            console.log('Role successfully required.');
            resolve();
          });
      });
    });
  });

  it('should deny access when a required role is not present', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .get(server + '/admin')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .then(() => {
            reject('Admin access should have been rejected!');
          })
          .catch(err => {
            expect(err.status).to.equal(403);
            console.log('Admin access successfully denied.');
            resolve();
          });
      });
    });
  });

  it('should generate a forgot password token', function () {
    const spySendMail = sinon.spy(app.superlogin.mailer, 'sendEmail');
    const emitterPromise = new Promise<void>(resolve => {
      app.superlogin.emitter.on('forgot-password', () => {
        resolve();
      });
    });

    return previous.then(() => {
      return Promise.all([
        request
          .post(server + '/auth/forgot-password')
          .send({ email: newUser.email }),
        emitterPromise
      ]).then(res => {
        expect(res[0].status).to.equal(200);
        const sendEmailArgs = spySendMail.getCall(0).args;
        resetToken = sendEmailArgs[2].token;
        console.log('Password token successfully generated.');
        return Promise.resolve();
      });
    });
  });

  it('should reset the password', function () {
    return previous.then(function () {
      return findUser(newUser.username).then(() => {
        return new Promise<void>(function (resolve, reject) {
          request
            .post(server + '/auth/password-reset')
            .send({
              token: resetToken,
              password: 'newpass1',
              confirmPassword: 'newpass1'
            })
            .then(res => {
              expect(res.status).to.equal(200);
              console.log('Password successfully reset.');
              resolve();
            });
        });
      });
    });
  });

  it('should logout the user upon password reset', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .get(server + '/auth/session')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .then(() => {
            reject('User should have been logged out!');
          })
          .catch(err => {
            expect(err.status).to.equal(401);
            console.log(
              'User has been successfully logged out on password reset.'
            );
            resolve();
          });
      });
    });
  });

  it('should login with the new password', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .post(server + '/auth/login')
          .send({ username: newUser.username, password: 'newpass1' })
          .then(res => {
            accessToken = res.body.token;
            accessPass = res.body.password;
            expireCompare = res.body.expires;
            expect(res.status).to.equal(200);
            expect(res.body.roles[0]).to.equal('user');
            expect(res.body.token.length).to.be.above(10);
            console.log('User successfully logged in with new password');
            resolve();
          })
          .catch(err => {
            return reject('Failed to log in. ' + err);
          });
      });
    });
  });

  it('should refresh the session', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .post(server + '/auth/refresh')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .then(res => {
            expect(res.status).to.equal(200);
            expect(res.body.expires).to.be.above(expireCompare);
            return keysDB.get('org.couchdb.user:' + accessToken);
          })
          .then(tokenDoc => {
            expect(tokenDoc.expires).to.be.above(expireCompare);
            console.log('Session successfully refreshed.');
            resolve();
          });
      });
    });
  });

  it('should retrieve the current consents', async () => {
    const res = await request
      .get(server + '/auth/consents')
      .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
      .send();
    expect(res.status).to.equal(200);
    expect(res.body.privacy.version).to.equal(3);
    expect(res.body.marketing.accepted).to.equal(false);
  });

  it('should update the consents', async () => {
    const data = {
      marketing: {
        accepted: true,
        version: 3
      }
    };
    const res = await request
      .post(server + '/auth/consents')
      .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
      .send(data);
    expect(res.status).to.equal(200);
    expect(res.body.privacy.accepted).to.equal(true);
    expect(res.body.marketing.accepted).to.equal(true);
    expect(res.body.marketing.version).to.equal(3);
  });

  it('should change the password', function () {
    return previous.then(function () {
      return findUser(newUser.username).then(function (resetUser) {
        return new Promise<void>(function (resolve, reject) {
          request
            .post(server + '/auth/password-change')
            .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
            .send({
              currentPassword: 'newpass1',
              newPassword: 'newpass2',
              confirmPassword: 'newpass2'
            })
            .then(res => {
              expect(res.status).to.equal(200);
              console.log('Password successfully changed.');
              resolve();
            });
        });
      });
    });
  });

  it('should change the email', () => {
    return previous.then(function () {
      return findUser(newUser.username).then(function (_user) {
        return new Promise<void>(function (resolve, reject) {
          request
            .post(server + '/auth/change-email')
            .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
            .send({
              newEmail: 'kewluzer2@example.com',
              password: 'newpass2',
              username: 'kewluzer@example.com'
            })
            .then(res => {
              expect(res.status).to.equal(200);
              return timeoutPromise(300);
            })
            .then(() => {
              resolve();
            })
            .catch(err => {
              console.error(err);
            });
        });
      });
    });
  });

  it('should logout the user', function () {
    return previous.then(function () {
      return new Promise<void>(function (resolve, reject) {
        request
          .post(server + '/auth/logout')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function (error, res) {
            if (error || res.status !== 200) {
              throw new Error('Failed to logout the user.');
            }
            expect(res.status).to.equal(200);
            resolve();
          });
      }).then(function () {
        return new Promise<void>(function (resolve, reject) {
          request
            .get(server + '/auth/session')
            .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
            .end(function (error, res) {
              expect(res.status).to.equal(401);
              console.log('User has been successfully logged out.');
              resolve();
            });
        });
      });
    });
  });

  it('should login after creating a new user', function () {
    return previous.then(function () {
      app.config.security.loginOnRegistration = true;
      return new Promise<void>(function (resolve, reject) {
        request
          .post(server + '/auth/register')
          .send(newUser2)
          .end(function (error, res) {
            expect(res.status).to.equal(200);
            expect(res.body.token).to.be.string;
            console.log('User created and logged in');
            newUser2Bearer = res.body.token + ':' + res.body.password;
            resolve();
          });
      });
    });
  });

  it('should validate a username', function () {
    return previous
      .then(function () {
        return new Promise<void>(function (resolve, reject) {
          request
            .get(server + '/auth/validate-username/idontexist')
            .end(function (error, res) {
              expect(res.status).to.equal(200);
              expect(res.body.ok).to.equal(true);
              resolve();
            });
        });
      })
      .then(function () {
        return new Promise<void>(function (resolve, reject) {
          request
            .get(server + '/auth/validate-username/kewluzer')
            .end(function (error, res) {
              expect(res.status).to.equal(409);
              console.log('Validate Username is working');
              resolve();
            });
        });
      });
  });

  it('should validate an email', function () {
    return previous
      .then(function () {
        return new Promise<void>(function (resolve, reject) {
          request
            .get(server + '/auth/validate-email/nobody@example.com')
            .end(function (error, res) {
              expect(res.status).to.equal(200);
              expect(res.body.ok).to.equal(true);
              resolve();
            });
        });
      })
      .then(() => {
        return new Promise<void>((resolve, reject) => {
          request
            .get(server + '/auth/validate-email/nobody@example')
            .end((err, res) => {
              expect(res.status).to.equal(400);
              resolve();
            });
        });
      })
      .then(function () {
        return new Promise<void>(function (resolve, reject) {
          request
            .get(server + '/auth/validate-username/kewluzer2@example.com')
            .end(function (error, res) {
              expect(res.status).to.equal(409);
              console.log('Validate Email is working');
              resolve();
            });
        });
      });
  });

  function attemptLogin(username, password) {
    return new Promise(function (resolve, reject) {
      request
        .post(server + '/auth/login')
        .send({ username: username, password: password })
        .end(function (error, res) {
          resolve({ status: res.status, message: res.body.message });
        });
    });
  }

  it('should respond unauthorized on login if no password is set', function () {
    return previous
      .then(function () {
        return userDB.insert({
          _id: 'nopassword',
          email: 'nopassword@example.com'
        });
      })
      .then(function () {
        return attemptLogin('nopassword', 'wrongpassword');
      })
      .then(function (result: any) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Invalid username or password');
      });
  });

  it('should respond unauthorized on login if the password is wrong', function () {
    return previous
      .then(function () {
        return attemptLogin('kewluzer', 'wrong');
      })
      .then(function (result: any) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Invalid username or password');
        return Promise.resolve();
      });
  });

  it('should respond unauthorized on login if data is missing', function () {
    return previous
      .then(function () {
        return attemptLogin(undefined, 'test');
      })
      .then(function (result: any) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Missing credentials');
        return Promise.resolve();
      });
  });

  it('should delete a user', () => {
    const emitterPromise = new Promise<void>(function (resolve) {
      app.superlogin.emitter.on('user-deleted', function (user, reason) {
        expect(user.key).to.equal(newUser2.username);
        expect(reason).to.equal('boring');
        resolve();
      });
    });

    return previous.then(() => {
      const deletionForm = {
        password: newUser2.password,
        username: newUser2.username,
        reason: 'boring'
      };
      const requestPromise = new Promise<void>(resolve => {
        request
          .post(server + '/auth/request-deletion')
          .set('Authorization', 'Bearer ' + newUser2Bearer)
          .send(deletionForm)
          .end(function (error, res) {
            expect(res.status).to.equal(200);
            resolve();
          });
      });
      return Promise.all([requestPromise, emitterPromise]);
    });
  });
});
