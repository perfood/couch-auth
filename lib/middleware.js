// Contains middleware useful for securing your routes
'use strict';
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
};
var _passport;
Object.defineProperty(exports, "__esModule", { value: true });
class Middleware {
    constructor(passport) {
        _passport.set(this, void 0);
        __classPrivateFieldSet(this, _passport, passport);
    }
    /** Requires that the user be authenticated with a bearer token */
    requireAuth(req, res, next) {
        __classPrivateFieldGet(this, _passport).authenticate('bearer', { session: false })(req, res, next);
    }
    // Requires that the user have the specified role
    requireRole(requiredRole) {
        return (req, res, next) => {
            if (!req.user) {
                return next(Middleware.superloginError);
            }
            // @ts-ignore
            const roles = req.user.roles;
            if (!roles || !roles.length || roles.indexOf(requiredRole) === -1) {
                res.status(Middleware.forbiddenError.status);
                res.json(Middleware.forbiddenError);
            }
            else {
                next();
            }
        };
    }
    /** Requires that the user have at least one of the specified roles */
    requireAnyRole(possibleRoles) {
        return (req, res, next) => {
            if (!req.user) {
                return next(Middleware.superloginError);
            }
            let denied = true;
            // @ts-ignore
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
            }
            else {
                next();
            }
        };
    }
    requireAllRoles(requiredRoles) {
        return (req, res, next) => {
            if (!req.user) {
                return next(Middleware.superloginError);
            }
            let denied = false;
            const roles = req.user.roles;
            if (!roles || !roles.length) {
                denied = true;
            }
            else {
                for (let i = 0; i < requiredRoles.length; i++) {
                    if (roles.indexOf(requiredRoles[i]) === -1) {
                        denied = true;
                    }
                }
            }
            if (denied) {
                res.status(Middleware.forbiddenError.status);
                res.json(Middleware.forbiddenError);
            }
            else {
                next();
            }
        };
    }
}
exports.Middleware = Middleware;
_passport = new WeakMap();
Middleware.forbiddenError = {
    error: 'Forbidden',
    message: 'You do not have permission to access this resource.',
    status: 403
};
Middleware.superloginError = {
    error: 'superlogin',
    message: 'requireAuth must be used before checking roles',
    status: 500
};
