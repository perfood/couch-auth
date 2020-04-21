'use strict';

import { capitalizeFirstLetter } from './util';
import { Request, Response, Router, NextFunction } from 'express';
import { Authenticator } from 'passport';
import { User } from './user';
import { ConfigHelper } from './config/configure';
import { callbackify } from 'util';

const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const extend = require('util')._extend;
const stateRequired = ['google', 'linkedin'];

module.exports = function (
  router: Router,
  passport: Authenticator,
  user: User,
  config: ConfigHelper
) {
  // Function to initialize a session following authentication from a socialAuth provider
  function initSession(req: Request, res: Response, next: NextFunction) {
    const provider = getProvider(req.path);
    return (
      user
        // @ts-ignore
        .createSession(req.user._id, provider, req)
        .then(function (mySession) {
          return Promise.resolve({
            error: null,
            session: mySession,
            link: null
          });
        })
        .then(
          function (results) {
            let template;
            if (config.getItem('testMode.oauthTest')) {
              template = fs.readFileSync(
                path.join(
                  __dirname,
                  '../templates/oauth/auth-callback-test.ejs'
                ),
                'utf8'
              );
            } else {
              template = fs.readFileSync(
                path.join(__dirname, '../templates/oauth/auth-callback.ejs'),
                'utf8'
              );
            }
            const html = ejs.render(template, results);
            res.status(200).send(html);
          },
          function (err) {
            return next(err);
          }
        )
    );
  }

  // Function to initialize a session following authentication from a socialAuth provider
  function initTokenSession(req: Request, res: Response, next: NextFunction) {
    const provider = getProviderToken(req.path);
    return (
      user
        // @ts-ignore
        .createSession(req.user._id, provider, req)
        .then(function (mySession) {
          return Promise.resolve(mySession);
        })
        .then(
          function (session) {
            res.status(200).json(session);
          },
          function (err) {
            return next(err);
          }
        )
    );
  }

  // Called after an account has been succesfully linked
  function linkSuccess(req: Request, res: Response, next: NextFunction) {
    const provider = getProvider(req.path);
    const result = {
      error: null,
      session: null,
      link: provider
    };
    let template;
    if (config.getItem('testMode.oauthTest')) {
      template = fs.readFileSync(
        path.join(__dirname, '../templates/oauth/auth-callback-test.ejs'),
        'utf8'
      );
    } else {
      template = fs.readFileSync(
        path.join(__dirname, '../templates/oauth/auth-callback.ejs'),
        'utf8'
      );
    }
    const html = ejs.render(template, result);
    res.status(200).send(html);
  }

  // Called after an account has been succesfully linked using access_token provider
  function linkTokenSuccess(req: Request, res: Response, next: NextFunction) {
    const provider = getProviderToken(req.path);
    res.status(200).json({
      ok: true,
      success: capitalizeFirstLetter(provider) + ' successfully linked',
      provider: provider
    });
  }

  // Handles errors if authentication fails
  function oauthErrorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    let template;
    if (config.getItem('testMode.oauthTest')) {
      template = fs.readFileSync(
        path.join(__dirname, '../templates/oauth/auth-callback-test.ejs'),
        'utf8'
      );
    } else {
      template = fs.readFileSync(
        path.join(__dirname, '../templates/oauth/auth-callback.ejs'),
        'utf8'
      );
    }
    const html = ejs.render(template, {
      error: err.message,
      session: null,
      link: null
    });
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
    }
    res.status(400).send(html);
  }

  // Handles errors if authentication from access_token provider fails
  function tokenAuthErrorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    let status;
    // @ts-ignore
    if (req.user && req.user._id) {
      status = 403;
    } else {
      status = 401;
    }
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
      delete err.stack;
    }
    res.status(status).json(err);
  }

  // Framework to register OAuth providers with passport
  function registerProvider(provider: string, configFunction: Function) {
    provider = provider.toLowerCase();
    const configRef = 'providers.' + provider;
    if (config.getItem(configRef + '.credentials')) {
      const credentials = config.getItem(configRef + '.credentials');
      credentials.passReqToCallback = true;
      const options = config.getItem(configRef + '.options') || {};
      configFunction.call(null, credentials, passport, authHandler);
      router.get('/' + provider, passportCallback(provider, options, 'login'));
      router.get(
        '/' + provider + '/callback',
        passportCallback(provider, options, 'login'),
        initSession,
        oauthErrorHandler
      );
      if (!config.getItem('security.disableLinkAccounts')) {
        router.get(
          '/link/' + provider,
          passport.authenticate('bearer', { session: false }),
          passportCallback(provider, options, 'link')
        );
        router.get(
          '/link/' + provider + '/callback',
          passport.authenticate('bearer', { session: false }),
          passportCallback(provider, options, 'link'),
          linkSuccess,
          oauthErrorHandler
        );
      }
      console.log(provider + ' loaded.');
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  function registerOAuth2(providerName: string, Strategy: any) {
    registerProvider(providerName, function (
      credentials,
      passport: Authenticator,
      authHandler: (
        req: Request,
        provider: string,
        auth,
        profile
      ) => Promise<any>
    ) {
      passport.use(
        new Strategy(credentials, function (
          req,
          accessToken,
          refreshToken,
          profile,
          done
        ) {
          callbackify(authHandler)(
            req,
            providerName,
            { accessToken: accessToken, refreshToken: refreshToken },
            profile,
            done
          );
        })
      );
    });
  }

  // Registers a provider that accepts an access_token directly from the client, skipping the popup window and callback
  // This is for supporting Cordova, native IOS and Android apps, as well as other devices
  function registerTokenProvider(providerName: string, Strategy) {
    providerName = providerName.toLowerCase();
    const configRef = 'providers.' + providerName;
    if (config.getItem(configRef + '.credentials')) {
      const credentials = config.getItem(configRef + '.credentials');
      credentials.passReqToCallback = true;
      const options = config.getItem(configRef + '.options') || {};
      // Configure the Passport Strategy
      passport.use(
        providerName + '-token',
        new Strategy(credentials, function (
          req,
          accessToken,
          refreshToken,
          profile,
          done
        ) {
          callbackify(authHandler)(
            req,
            providerName,
            { accessToken: accessToken, refreshToken: refreshToken },
            profile,
            done
          );
        })
      );
      router.post(
        '/' + providerName + '/token',
        passportTokenCallback(providerName, options),
        initTokenSession,
        tokenAuthErrorHandler
      );
      if (!config.getItem('security.disableLinkAccounts')) {
        router.post(
          '/link/' + providerName + '/token',
          passport.authenticate('bearer', { session: false }),
          passportTokenCallback(providerName, options),
          linkTokenSuccess,
          tokenAuthErrorHandler
        );
      }
      console.log(providerName + '-token loaded.');
    }
  }

  // This is called after a user has successfully authenticated with a provider
  // If a user is authenticated with a bearer token we will link an account, otherwise log in
  // auth is an object containing 'access_token' and optionally 'refresh_token'
  function authHandler(req: Request, provider: string, auth, profile) {
    //@ts-ignore
    if (req.user && req.user._id && req.user.key) {
      //@ts-ignore
      return user.linkSocial(req.user._id, provider, auth, profile, req);
    } else {
      return user.socialAuth(provider, auth, profile, req);
    }
  }

  // Configures the passport.authenticate for the given provider, passing in options
  // Operation is 'login' or 'link'
  function passportCallback(provider: string, options, operation) {
    return function (req: Request, res: Response, next: NextFunction) {
      const theOptions = extend({}, options);
      if (provider === 'linkedin') {
        theOptions.state = true;
      }
      const accessToken = req.query.bearer_token || req.query.state;
      if (
        accessToken &&
        (stateRequired.indexOf(provider) > -1 ||
          config.getItem('providers.' + provider + '.stateRequired') === true)
      ) {
        theOptions.state = accessToken;
      }
      theOptions.callbackURL = getLinkCallbackURLs(
        provider,
        req,
        operation,
        accessToken
      );
      theOptions.session = false;
      passport.authenticate(provider, theOptions)(req, res, next);
    };
  }

  // Configures the passport.authenticate for the given access_token provider, passing in options
  function passportTokenCallback(provider: string, options) {
    return function (req: Request, res: Response, next: NextFunction) {
      const theOptions = extend({}, options);
      theOptions.session = false;
      passport.authenticate(provider + '-token', theOptions)(req, res, next);
    };
  }

  function getLinkCallbackURLs(
    provider: string,
    req: Request,
    operation,
    accessToken
  ) {
    if (accessToken) {
      accessToken = encodeURIComponent(accessToken);
    }
    const protocol = (req.get('X-Forwarded-Proto') || req.protocol) + '://';
    if (operation === 'login') {
      return (
        protocol + req.get('host') + req.baseUrl + '/' + provider + '/callback'
      );
    }
    if (operation === 'link') {
      let reqUrl;
      if (
        accessToken &&
        (stateRequired.indexOf(provider) > -1 ||
          config.getItem('providers.' + provider + '.stateRequired') === true)
      ) {
        reqUrl =
          protocol +
          req.get('host') +
          req.baseUrl +
          '/link/' +
          provider +
          '/callback';
      } else {
        reqUrl =
          protocol +
          req.get('host') +
          req.baseUrl +
          '/link/' +
          provider +
          '/callback?state=' +
          accessToken;
      }
      return reqUrl;
    }
  }

  /** Gets the provider name from a callback path */
  function getProvider(pathname: string) {
    const items = pathname.split('/');
    const index = items.indexOf('callback');
    if (index > 0) {
      return items[index - 1];
    }
  }

  /** Gets the provider name from a callback path for access_token strategy */
  function getProviderToken(pathname: string) {
    const items = pathname.split('/');
    const index = items.indexOf('token');
    if (index > 0) {
      return items[index - 1];
    }
  }

  return {
    registerProvider: registerProvider,
    registerOAuth2: registerOAuth2,
    registerTokenProvider: registerTokenProvider
  };
};
