'use strict';
import { NextFunction, Request, Response, Router } from 'express';
import { Authenticator } from 'passport';
import { Config } from './types/config';
import { SlRequest } from './types/typings';
import { User, ValidErr } from './user';
import {
  capitalizeFirstLetter,
  getSessionToken,
  isUserFacingError
} from './util';

export default function (
  config: Partial<Config>,
  router: Router,
  passport: Authenticator,
  user: User
) {
  const env = process.env.NODE_ENV || 'development';
  const disabled: string[] = config.security.disabledRoutes;

  function loginLocal(req, res, next) {
    passport.authenticate('local', function (err, user, info) {
      if (err) {
        return next(err);
      }
      if (!user) {
        // Authentication failed
        return res.status(401).json(info);
      }
      // Success
      req.logIn(user, { session: false }, function (err) {
        if (err) {
          return next(err);
        }
      });
      return next();
    })(req, res, next);
  }

  if (!disabled.includes('login'))
    router.post(
      '/login',
      function (req, res, next) {
        loginLocal(req, res, next);
      },
      function (req: SlRequest, res, next) {
        return user
          .createSession({
            login: req.user._id,
            provider: 'local',
            byUUID: true,
            sessionType: req.body.sessionType
          })
          .then(
            function (mySession) {
              res.status(200).json(mySession);
            },
            function (err) {
              return next(err);
            }
          );
      }
    );

  if (!disabled.includes('refresh'))
    router.post(
      '/refresh',
      passport.authenticate('bearer', { session: false }),
      function (req: SlRequest, res: Response, next: NextFunction) {
        return user.refreshSession(req.user.key).then(
          function (mySession) {
            res.status(200).json(mySession);
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('logout'))
    router.post(
      '/logout',
      function (req: Request, res: Response, next: NextFunction) {
        const sessionToken = getSessionToken(req);
        if (!sessionToken) {
          return next({
            error: 'unauthorized',
            status: 401
          });
        }
        user.logoutSession(sessionToken).then(
          function () {
            res.status(200).json({ ok: true, success: 'Logged out' });
          },
          function (err) {
            console.error('Logout failed');
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('logout-others'))
    router.post(
      '/logout-others',
      passport.authenticate('bearer', { session: false }),
      function (req: SlRequest, res: Response, next: NextFunction) {
        user.logoutOthers(req.user.key).then(
          function () {
            res.status(200).json({ success: 'Other sessions logged out' });
          },
          function (err) {
            console.error('Logout failed');
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('logout-all'))
    router.post(
      '/logout-all',
      function (req: Request, res: Response, next: NextFunction) {
        const sessionToken = getSessionToken(req);
        if (!sessionToken) {
          return next({
            error: 'unauthorized',
            status: 401
          });
        }
        user.logoutAll(null, sessionToken).then(
          function () {
            res.status(200).json({ success: 'Logged out' });
          },
          function (err) {
            console.error('Logout-all failed');
            return next(err);
          }
        );
      }
    );

  // Setting up the auth api
  if (!disabled.includes('register'))
    router.post(
      '/register',
      function (req: Request, res: Response, next: NextFunction) {
        user.createUser(req.body, req).then(
          function (newUser) {
            if (!newUser || !config.security.loginOnRegistration) {
              res.status(200).json({ success: 'Request processed.' });
            } else if (newUser && config.security.loginOnRegistration) {
              return user
                .createSession({
                  login: newUser._id,
                  provider: 'local',
                  byUUID: true,
                  sessionType: req.body.sessionType
                })
                .then(
                  function (mySession) {
                    res.status(200).json(mySession);
                  },
                  function (err) {
                    return next(err);
                  }
                );
            }
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('forgot-username')) {
    router.post(
      '/forgot-username',
      function (req: Request, res: Response, next: NextFunction) {
        user.forgotUsername(req.body.email, req).then(
          function () {
            res.status(200).json({ success: 'Request processed.' });
          },
          function (err) {
            return next(err);
          }
        );
      }
    );
  }

  if (!disabled.includes('forgot-password'))
    router.post(
      '/forgot-password',
      function (req: Request, res: Response, next: NextFunction) {
        user.forgotPassword(req.body.email, req).then(
          function () {
            res.status(200).json({ success: 'Request processed.' });
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('password-reset'))
    router.post(
      '/password-reset',
      function (req: Request, res: Response, next: NextFunction) {
        user.resetPassword(req.body, req).then(
          function (currentUser) {
            if (config.security.loginOnPasswordReset) {
              return user
                .createSession({
                  login: currentUser._id,
                  provider: 'local',
                  byUUID: true,
                  sessionType: req.body.sessionType
                })
                .then(
                  function (mySession) {
                    res.status(200).json(mySession);
                  },
                  function (err) {
                    return next(err);
                  }
                );
            } else {
              res.status(200).json({ success: 'Password successfully reset.' });
            }
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('password-change'))
    router.post(
      '/password-change',
      passport.authenticate('bearer', { session: false }),
      function (req: SlRequest, res: Response, next: NextFunction) {
        user.changePasswordSecure(req.user._id, req.body, req).then(
          function () {
            res.status(200).json({ success: 'password changed' });
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('unlink'))
    router.post(
      '/unlink/:provider',
      passport.authenticate('bearer', { session: false }),
      function (req: SlRequest, res: Response, next: NextFunction) {
        const provider = req.params.provider;
        user.unlinkUserSocial(req.user._id, provider).then(
          function () {
            res.status(200).json({
              success: capitalizeFirstLetter(provider) + ' unlinked'
            });
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('confirm-email'))
    router.get(
      '/confirm-email/:token',
      function (req: Request, res: Response, next: NextFunction) {
        const redirectURL = config.local.confirmEmailRedirectURL;
        if (!req.params.token) {
          const err = { error: 'Email verification token required' };
          if (redirectURL) {
            return res
              .status(201)
              .redirect(
                redirectURL + '?error=' + encodeURIComponent(err.error)
              );
          }
          return res.status(400).send(err);
        }
        user.verifyEmail(req.params.token).then(
          function () {
            if (redirectURL) {
              return res.status(201).redirect(redirectURL + '?success=true');
            }
            res.status(200).send({ ok: true, success: 'Email verified' });
          },
          function (err) {
            if (redirectURL) {
              let query = '?error=' + encodeURIComponent(err.error);
              if (err.message) {
                query += '&message=' + encodeURIComponent(err.message);
              }
              return res.status(201).redirect(redirectURL + query);
            }
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('validate-username'))
    router.get(
      '/validate-username/:username',
      function (req: Request, res: Response, next: NextFunction) {
        if (!req.params.username) {
          return next({ error: 'Username required', status: 400 });
        }
        user.validateUsername(req.params.username).then(
          function (err_msg) {
            if (!err_msg) {
              res.status(200).json({ ok: true });
            } else {
              res.status(409).json({ error: err_msg });
            }
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('validate-email'))
    router.get(
      '/validate-email/:email',
      function (req: Request, res: Response, next: NextFunction) {
        if (!req.params.email) {
          return next({ error: 'Email required', status: 400 });
        }
        user.validateEmail(req.params.email).then(
          function (err) {
            if (!err) {
              res.status(200).json({ ok: true });
            } else if (err === ValidErr.emailInvalid) {
              res.status(400).json({ error: ValidErr.emailInvalid });
            } else {
              res.status(409).json({ error: 'Email already in use' });
            }
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('request-deletion'))
    router.post(
      '/request-deletion',
      passport.authenticate('bearer', { session: false }),
      (req: Request, res: Response, next: NextFunction) => {
        loginLocal(req, res, next);
      },
      (req: SlRequest, res: Response, next: NextFunction) => {
        if (req.body.reason && typeof req.body.reason !== 'string') {
          return res.sendStatus(400);
        }
        res.status(200).json({
          ok: true,
          success: 'deletion requested'
        });
        user.removeUser(req.user._id, true, req.body.reason).catch(err => {
          console.warn('request-deletion: failed for ', req.user._id, err);
        });
      }
    );

  if (!disabled.includes('change-email'))
    router.post(
      '/change-email',
      passport.authenticate('bearer', { session: false }),
      function (req: Request, res: Response, next: NextFunction) {
        if (config.local.requirePasswordOnEmailChange) {
          loginLocal(req, res, next);
        } else {
          next(req);
        }
      },
      function (req: SlRequest, res: Response, next: NextFunction) {
        const login = config.local.requirePasswordOnEmailChange
          ? req.user.key
          : req.user._id;
        user.changeEmail(login, req.body.newEmail, req).then(
          function () {
            res
              .status(200)
              .json({ ok: true, success: 'Email change requested' });
          },
          function (err) {
            return next(err);
          }
        );
      }
    );

  if (!disabled.includes('session'))
    router.get(
      '/session',
      passport.authenticate('bearer', { session: false }),
      function (req: SlRequest, res: Response) {
        const user = req.user;
        user.user_id = user._id; // todo: should rename/make clear what's used
        delete user._id;
        delete user.key;
        res.status(200).json(user);
      }
    );

  if (!disabled.includes('consents') && config.local.consents) {
    router.get(
      '/consents',
      passport.authenticate('bearer', { session: false }),
      (req: SlRequest, res: Response, next: NextFunction) => {
        user
          .getCurrentConsents(req.user._id)
          .then(consents => res.status(200).json(consents))
          .catch(err => next(err));
      }
    );

    router.post(
      '/consents',
      passport.authenticate('bearer', { session: false }),
      (req: SlRequest, res: Response, next: NextFunction) => {
        user
          .updateConsents(req.user._id, req.body)
          .then(ret => res.status(200).json(ret))
          .catch(err => next(err));
      }
    );
  }

  /**
   * If the error is expected, it's sent as response. Otherwise, a generic
   * server error without detailed information is returned when in production.
   */
  router.use(function (err, req: Request, res: Response, next: NextFunction) {
    const isExpected = isUserFacingError(err);
    if (!isExpected) {
      const errLog =
        typeof err === 'string' ? err : err.reason ? err.reason : err.message;
      console.error(errLog);
      if (err.stack) {
        console.error(err.stack);
      }
    }
    if (env !== 'development') {
      isExpected
        ? res.status(err.status).json(err)
        : res.status(500).json({ status: 500, error: 'Internal Server Error' });
    } else {
      res.status(err.status || 500).json(err);
    }
  });
}
