'use strict';
const expect = require('chai').expect;
const Middleware = require('../lib/middleware').Middleware;

const middleware = new Middleware({});

const noCall = function () {
  throw new Error('This should not have been called.');
};

// eslint-disable-next-line
const noop = function () {};

describe('middleware', function () {
  describe('requireRole', function () {
    it('should pass when a required role is present', function (done) {
      const req = {
        user: {
          roles: ['user']
        }
      };
      const res = {
        status: noCall,
        json: noop
      };
      const next = function () {
        done();
      };
      middleware.requireRole('user')(req, res, next);
    });

    it('should fail when a required role is missing', function (done) {
      const req = {
        user: {
          roles: ['user']
        }
      };
      const res = {
        status: function (num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireRole('admin')(req, res, noCall);
    });
  });

  describe('requireAnyRole', function () {
    it('should pass when at least one of the required roles is present', function (done) {
      const req = {
        user: {
          roles: ['user']
        }
      };
      const res = {
        status: noCall,
        json: noop
      };
      const next = function () {
        done();
      };
      middleware.requireAnyRole(['user', 'admin'])(req, res, next);
    });

    it('should fail when no required role is present', function (done) {
      const req = {
        user: {
          roles: ['user']
        }
      };
      const res = {
        status: function (num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireAnyRole(['admin', 'superman'])(req, res, noCall);
    });
  });

  describe('requireAllRoles', function () {
    it('should pass when all of the roles are present', function (done) {
      const req = {
        user: {
          roles: ['user', 'admin', 'superman']
        }
      };
      const res = {
        status: noCall,
        json: noop
      };
      const next = function () {
        done();
      };
      middleware.requireAllRoles(['user', 'admin'])(req, res, next);
    });

    it('should fail when just one required role is missing', function (done) {
      const req = {
        user: {
          roles: ['user', 'admin']
        }
      };
      const res = {
        status: function (num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireAllRoles(['admin', 'superman'])(req, res, noCall);
    });
  });
});
