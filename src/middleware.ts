// Contains middleware useful for securing your routes
'use strict';

export class Middleware {
  static forbiddenError = {
    error: 'Forbidden',
    message: 'You do not have permission to access this resource.',
    status: 403
  };

  static superloginError = {
    error: 'superlogin',
    message: 'requireAuth must be used before checking roles',
    status: 500
  };
  #passport;
  constructor(passport) {
    this.#passport = passport;
  }

  /** Requires that the user be authenticated with a bearer token */
  requireAuth(req, res, next) {
    this.#passport.authenticate('bearer', { session: false })(req, res, next);
  }

  // Requires that the user have the specified role
  requireRole(requiredRole: string) {
    return (req, res, next) => {
      if (!req.user) {
        return next(Middleware.superloginError);
      }
      const roles = req.user.roles;
      if (!roles || !roles.length || roles.indexOf(requiredRole) === -1) {
        res.status(Middleware.forbiddenError.status);
        res.json(Middleware.forbiddenError);
      } else {
        next();
      }
    };
  }

  /** Requires that the user have at least one of the specified roles */
  requireAnyRole(possibleRoles: string[]) {
    return (req, res, next) => {
      if (!req.user) {
        return next(Middleware.superloginError);
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
        res.status(Middleware.forbiddenError.status);
        res.json(Middleware.forbiddenError);
      } else {
        next();
      }
    };
  }

  requireAllRoles(requiredRoles: string[]) {
    return (req, res, next) => {
      if (!req.user) {
        return next(Middleware.superloginError);
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
        res.status(Middleware.forbiddenError.status);
        res.json(Middleware.forbiddenError);
      } else {
        next();
      }
    };
  }
}
