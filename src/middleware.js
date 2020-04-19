// Contains middleware useful for securing your routes
'use strict';

export class Middleware {
  constructor(passport) {
    const forbiddenError = {
      error: 'Forbidden',
      message: 'You do not have permission to access this resource.',
      status: 403
    };

    const superloginError = {
      error: 'superlogin',
      message: 'requireAuth must be used before checking roles',
      status: 500
    };

    // Requires that the user be authenticated with a bearer token
    this.requireAuth = function (req, res, next) {
      passport.authenticate('bearer', { session: false })(req, res, next);
    };

    // Requires that the user have the specified role
    this.requireRole = function (requiredRole) {
      return function (req, res, next) {
        if (!req.user) {
          return next(superloginError);
        }
        const roles = req.user.roles;
        if (!roles || !roles.length || roles.indexOf(requiredRole) === -1) {
          res.status(forbiddenError.status);
          res.json(forbiddenError);
        } else {
          next();
        }
      };
    };

    // Requires that the user have at least one of the specified roles
    this.requireAnyRole = function (possibleRoles) {
      return function (req, res, next) {
        if (!req.user) {
          return next(superloginError);
        }
        let denied = true;
        const roles = req.user.roles;
        if (roles && roles.length) {
          for (let i = 0; i < possibleRoles.length; i++) {
            if (roles.indexOf(possibleRoles[i]) !== -1) {
              denied = false;
            }
          }
        }
        if (denied) {
          res.status(forbiddenError.status);
          res.json(forbiddenError);
        } else {
          next();
        }
      };
    };

    this.requireAllRoles = function (requiredRoles) {
      return function (req, res, next) {
        if (!req.user) {
          return next(superloginError);
        }
        let denied = false;
        const roles = req.user.roles;
        if (!roles || !roles.length) {
          denied = true;
        } else {
          for (let i = 0; i < requiredRoles.length; i++) {
            if (roles.indexOf(requiredRoles[i]) === -1) {
              denied = true;
            }
          }
        }
        if (denied) {
          res.status(forbiddenError.status);
          res.json(forbiddenError);
        } else {
          next();
        }
      };
    };
  }
}
