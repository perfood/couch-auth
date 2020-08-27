'use strict';
import { Authenticator } from 'passport';
import { Config } from './types/config';
import { Strategy as LocalStrategy } from 'passport-local';
import { Request } from 'express';
import { SlUserDoc } from './types/typings';
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
      const parse = tokenPass.split(':');
      if (parse.length < 2) {
        done(null, false, { message: 'invalid token' });
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
            if (theuser) {
              // Check if the account is locked. todo: remove this functionality
              if (
                theuser.local &&
                theuser.local.lockedUntil &&
                theuser.local.lockedUntil > Date.now()
              ) {
                return done(null, false, {
                  error: 'Unauthorized',
                  message:
                    'Your account is currently locked. Please wait a few minutes and try again.'
                });
              }
              if (!theuser.local || !theuser.local.derived_key) {
                return done(null, false, invalidResponse());
              }
              user.verifyPassword(theuser.local, password).then(
                () => {
                  // Check if the email has been confirmed if it is required
                  if (config.local.requireEmailConfirm && !theuser.email) {
                    return done(null, false, {
                      message: 'You must confirm your email address.'
                    });
                  }
                  // Success!!!
                  return done(null, theuser);
                },
                err => {
                  if (!err) {
                    // Password didn't authenticate
                    return handleFailedLogin(theuser, req, done);
                  } else {
                    // Hashing function threw an error
                    return done(err);
                  }
                }
              );
            } else {
              // user not found
              return done(null, false, invalidResponse());
            }
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

  function handleFailedLogin(userDoc: SlUserDoc, req: Request, done: Function) {
    const invalid = invalidResponse();
    // @ts-ignore
    return user.handleFailedLogin(userDoc, req).then(locked => {
      if (locked) {
        invalid.message =
          'Maximum failed login attempts exceeded. Your account has been locked for ' +
          Math.round(config.security.lockoutTime / 60) +
          ' minutes.';
      }
      return done(null, false, invalid);
    });
  }
}
