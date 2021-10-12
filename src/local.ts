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
        err => {
          if (err instanceof Error) {
            done(err, false);
          } else {
            done(null, false, { message: err });
          }
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
        user.getUser(username).then(
          theuser => {
            const invalid = !theuser?.local?.derived_key;
            const hashInput = invalid ? {} : theuser.local;
            user.verifyPassword(hashInput, password).then(
              () => {
                // Prevent time based attack -> still do a hashing round
                if (invalid) {
                  return done(null, false, invalidResponse());
                }
                // Check if the email has been confirmed if it is required
                if (config.local.requireEmailConfirm && !theuser.email) {
                  return done(null, false, invalidResponse());
                }
                // Success!!!
                return done(null, theuser);
              },
              err => {
                if (err !== false) {
                  console.warn('LocalStrategy rejected with: ', err);
                }
                return done(null, false, invalidResponse());
              }
            );
          },
          err => {
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
