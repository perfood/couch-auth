'use strict';

import { expect } from 'chai';
import { SessionHashing } from '../src/session-hashing';
import { SecurityConfig } from '../lib/types/config';

let previous;

const config = {
  security: {
    sessionHashing: {
      iterations: 600000,
      pbkdf2Prf: 'sha256',
      keyLength: 32,
      saltLength: 16,
    }
  } as SecurityConfig
};

const session = new SessionHashing(config);
const testToken = {
  _id: 'colinskow',
  roles: ['admin', 'user'],
  key: 'test123',
  issued: Date.now(),
  expires: Date.now() + 50000,
  password_scheme: 'pbkdf2',
  iterations: 10,
  salt: '991bc3c09ff7322f7f1361e383a9d9f8',
  derived_key: 'e04e30ee0ef31d541f1fb731c9631a9f48fa5196'
};
const testTokenSha256 = {
  _id: 'colinskow',
  roles: ['admin', 'user'],
  key: 'test123',
  issued: Date.now(),
  expires: Date.now() + 50000,
  password_scheme: 'pbkdf2',
  pbkdf2_prf: 'sha256',
  iterations: 600000,
  salt: '1199ebf0987feded35fe60d18483fe94',
  derived_key: 'f3312650451e9aa0760a84c203b78925dd9429e47925dbf303811fdb634c0b46'
};
const badToken = {
  ...testToken,
  salt: 'salt',
  derived_key: 'key'
};
describe('Session', async function () {
  previous = Promise.resolve();

  it('should confirm a token and return it if valid', function (done) {
    previous.then(function () {
      return session
        .verifySessionPassword(testToken, 'pass123')
        .then(function (result) {
          console.log('confirmed valid token.');
          expect(result).to.equal(true);
          done();
        })
        .catch(function (err) {
          console.log('confirmToken - got err: ', err);
          done(err);
        });
    });
  });

    it('should confirm a sha256 token and return it if valid', function (done) {
    previous.then(function () {
      return session
        .verifySessionPassword(testTokenSha256, 'UWlIB4MARQO7PBpgKOnXjQ')
        .then(function (result) {
          console.log('confirmed valid token.');
          expect(result).to.equal(true);
          done();
        })
        .catch(function (err) {
          console.log('confirmToken - got err: ', err);
          done(err);
        });
    });
  });

  it('should reject a bad token', function (done) {
    previous.then(function () {
      return session.verifySessionPassword(badToken, 'pass123').then(function (result) {
        console.log('rejected invalid token');
        expect(result).to.equal(false);
        done();
      }).catch(function (err) {
        done(err);
      });
    });
  });

  it('should reject a wrong password', function (done) {
    previous.then(function () {
      session.verifySessionPassword(testToken, 'wrongpass').then(function (result) {
        console.log('rejected invalid token');
        expect(result).to.equal(false);
        done();
      }).catch(function (err) {
        done(err);
      });
    });
  });
});
