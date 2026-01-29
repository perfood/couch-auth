'use strict';
import { Request } from 'express';
import { Authenticator } from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Config } from './types/config';
import { User } from './user';

const BearerStrategy = require('passport-http-bearer-sl').Strategy;

export default function (
  config: Partial<Config>,
  passport: Authenticator,
  user: User
) {
  // API token strategy
  passport.use(
    new BearerStrategy((tokenPass: string, done: Function) => {
      if (!tokenPass || typeof tokenPass !== 'string') {
        return done(null, false, { message: 'invalid token' });
      }
      const parse = tokenPass.split(':');
      if (parse.length < 2) {
        return done(null, false, { message: 'invalid token' });
      }
      const token = parse[0];
      const password = parse[1];
      user.confirmSession(token, password).then(
        theuser => {
          done(null, theuser);
        },
        _err => {
          return done(null, false, { message: 'invalid token' });
        }
      );
    })
  );

  // Use local strategy
  passport.use(
    new LocalStrategy(
      {
        usernameField: config.local.usernameField || 'username',
        passwordField: config.local.passwordField || 'password',
        session: false,
        passReqToCallback: true
      },
      (req: Request, username: string, password: string, done: Function) => {
        const loginStart = performance.now();
        console.log(`[PROFILING] Login: Started for user ${username}`);
        
        const login = username.trim().toLowerCase();
        const getUserStart = performance.now();
        user.getUser(login).then(
          theuser => {
            console.log(`[PROFILING] Login: User lookup took ${(performance.now() - getUserStart).toFixed(2)}ms`);
            
            const invalid = !theuser?.local?.derived_key;
            const hashInput = invalid ? {} : theuser.local;
            
            const verifyStart = performance.now();
            user.verifyPassword(hashInput, password).then(
              () => {
                console.log(`[PROFILING] Login: Password verification took ${(performance.now() - verifyStart).toFixed(2)}ms`);
                
                // Prevent time based attack -> still do a hashing round
                if (invalid) {
                  console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (invalid user)`);
                  return done(null, false, invalidResponse());
                }
                // Check if the email has been confirmed if it is required
                if (config.local.requireEmailConfirm && !theuser.email) {
                  console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (unconfirmed email)`);
                  return done(null, false, invalidResponse());
                }
                // Success!!!
                if (config.security?.userHashing?.upgradeOnLogin === false) {
                  console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (no upgrade)`);
                  return done(null, theuser);
                }
                // Upgrade password hash if needed
                const upgradeStart = performance.now();
                user.upgradePasswordHashIfNeeded(theuser, password)
                  .then(() => {
                    console.log(`[PROFILING] Login: Password hash upgrade took ${(performance.now() - upgradeStart).toFixed(2)}ms`);
                    console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (success)`);
                    done(null, theuser);
                  })
                  .catch((err) => {
                    console.warn('upgradePasswordHashIfNeeded rejected with: ', err);
                    console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (upgrade failed)`);
                    done(null, theuser);
                  });
              },
              err => {
                console.log(`[PROFILING] Login: Password verification took ${(performance.now() - verifyStart).toFixed(2)}ms (failed)`);
                console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (wrong password)`);
                if (err !== false) {
                  console.warn('LocalStrategy rejected with: ', err);
                }
                return done(null, false, invalidResponse());
              }
            );
          },
          err => {
            console.log(`[PROFILING] Login: User lookup took ${(performance.now() - getUserStart).toFixed(2)}ms (error)`);
            console.log(`[PROFILING] Login: Total time ${(performance.now() - loginStart).toFixed(2)}ms (database error)`);
            // Database threw an error
            return done(err);
          }
        );
      }
    )
  );

  function invalidResponse() {
    return {
      error: 'Unauthorized',
      message: 'Invalid username or password'
    };
  }
}
