'use strict';
import { Authenticator } from 'passport';
import { ConfigHelper } from './config/configure';
import { Strategy as LocalStrategy } from 'passport-local';
import { Request } from 'express';
import { SlUserDoc } from './types/typings';
import { User } from './user';
import { verifyPassword } from './util';

const BearerStrategy = require('passport-http-bearer-sl').Strategy;

module.exports = function (
  config: ConfigHelper,
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
        usernameField: config.getItem('local.usernameField') || 'username',
        passwordField: config.getItem('local.passwordField') || 'password',
        session: false,
        passReqToCallback: true
      },
      (req: Request, username: string, password: string, done: Function) => {
        user.getUser(username).then(
          theuser => {
            if (theuser) {
              // Check if the account is locked
              if (
                theuser.local &&
                theuser.local.lockedUntil &&
                theuser.local.lockedUntil > Date.now()
              ) {
                return done(null, false, {
                  message:
                    'Your account is currently locked. Please wait a few minutes and try again.'
                });
              }
              if (!theuser.local || !theuser.local.derived_key) {
                return done(null, false, {
                  message: 'Invalid username or password'
                });
              }
              verifyPassword(theuser.local, password).then(
                () => {
                  // Check if the email has been confirmed if it is required
                  if (
                    config.getItem('local.requireEmailConfirm') &&
                    !theuser.email
                  ) {
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
              return done(null, false, {
                //error: 'Unauthorized',
                message: 'Invalid username or password'
              });
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

  function handleFailedLogin(userDoc: SlUserDoc, req: Request, done: Function) {
    const invalid = {
      error: 'Unauthorized',
      message: 'Invalid username or password'
    };
    // @ts-ignore
    return user.handleFailedLogin(userDoc, req).then(locked => {
      if (locked) {
        invalid.message =
          'Maximum failed login attempts exceeded. Your account has been locked for ' +
          Math.round(config.getItem('security.lockoutTime') / 60) +
          ' minutes.';
      }
      return done(null, false, invalid);
    });
  }
};
