'use strict';
import { NextFunction, Request, Response, Router } from 'express';

import { Authenticator } from 'passport';
import { callbackify } from 'util';
import { capitalizeFirstLetter } from './util';
import { ConfigHelper } from './config/configure';
import { join } from 'path';
import { readFileSync } from 'fs';
import { render } from 'ejs';
import { SlRequest } from './types/typings';
import { User } from './user';

export class OAuth {
  static stateRequired = ['google', 'linkedin'];

  constructor(
    private router: Router,
    private passport: Authenticator,
    private user: User,
    private config: ConfigHelper
  ) {}

  // Function to initialize a session following authentication from a socialAuth provider
  private initSession(req: SlRequest, res: Response, next: NextFunction) {
    const provider = this.getProvider(req.path);
    return this.user
      .createSession(req.user._id, provider, req)
      .then(mySession => {
        return Promise.resolve({
          error: null,
          session: mySession,
          link: null
        });
      })
      .then(
        results => {
          let template;
          if (this.config.getItem('testMode.oauthTest')) {
            template = readFileSync(
              join(__dirname, '../templates/oauth/auth-callback-test.ejs'),
              'utf8'
            );
          } else {
            template = readFileSync(
              join(__dirname, '../templates/oauth/auth-callback.ejs'),
              'utf8'
            );
          }
          const html = render(template, results);
          res.status(200).send(html);
        },
        err => {
          return next(err);
        }
      );
  }

  // Function to initialize a session following authentication from a socialAuth provider
  private initTokenSession(req: SlRequest, res: Response, next: NextFunction) {
    const provider = this.getProviderToken(req.path);
    return this.user
      .createSession(req.user._id, provider, req)
      .then(mySession => {
        return Promise.resolve(mySession);
      })
      .then(
        session => {
          res.status(200).json(session);
        },
        err => {
          return next(err);
        }
      );
  }

  // Called after an account has been succesfully linked
  private linkSuccess(req: Request, res: Response, next: NextFunction) {
    const provider = this.getProvider(req.path);
    const result = {
      error: null,
      session: null,
      link: provider
    };
    let template;
    if (this.config.getItem('testMode.oauthTest')) {
      template = readFileSync(
        join(__dirname, '../templates/oauth/auth-callback-test.ejs'),
        'utf8'
      );
    } else {
      template = readFileSync(
        join(__dirname, '../templates/oauth/auth-callback.ejs'),
        'utf8'
      );
    }
    const html = render(template, result);
    res.status(200).send(html);
  }

  // Called after an account has been succesfully linked using access_token provider
  private linkTokenSuccess(req: Request, res: Response, next: NextFunction) {
    const provider = this.getProviderToken(req.path);
    res.status(200).json({
      ok: true,
      success: capitalizeFirstLetter(provider) + ' successfully linked',
      provider: provider
    });
  }

  // Handles errors if authentication fails
  private oauthErrorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    let template;
    if (this.config.getItem('testMode.oauthTest')) {
      template = readFileSync(
        join(__dirname, '../templates/oauth/auth-callback-test.ejs'),
        'utf8'
      );
    } else {
      template = readFileSync(
        join(__dirname, '../templates/oauth/auth-callback.ejs'),
        'utf8'
      );
    }
    const html = render(template, {
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
  private tokenAuthErrorHandler(
    err: Error,
    req: SlRequest,
    res: Response,
    next: NextFunction
  ) {
    let status;
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
  public registerProvider(provider: string, configFunction: Function) {
    provider = provider.toLowerCase();
    const configRef = 'providers.' + provider;
    if (this.config.getItem(configRef + '.credentials')) {
      const credentials = this.config.getItem(configRef + '.credentials');
      credentials.passReqToCallback = true;
      const options = this.config.getItem(configRef + '.options') || {};
      configFunction.call(
        null,
        credentials,
        this.passport,
        this.authHandler.bind(this)
      );
      this.router.get(
        '/' + provider,
        this.passportCallback(provider, options, 'login')
      );
      this.router.get(
        '/' + provider + '/callback',
        this.passportCallback(provider, options, 'login'),
        this.initSession.bind(this),
        this.oauthErrorHandler.bind(this)
      );
      if (!this.config.getItem('security.disableLinkAccounts')) {
        this.router.get(
          '/link/' + provider,
          this.passport.authenticate('bearer', { session: false }),
          this.passportCallback(provider, options, 'link')
        );
        this.router.get(
          '/link/' + provider + '/callback',
          this.passport.authenticate('bearer', { session: false }),
          this.passportCallback(provider, options, 'link'),
          this.linkSuccess.bind(this),
          this.oauthErrorHandler.bind(this)
        );
      }
      console.log(provider + ' loaded.');
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  public registerOAuth2(providerName: string, Strategy: any) {
    this.registerProvider(
      providerName,
      (
        credentials,
        passport: Authenticator,
        authHandler: (
          req: Request,
          provider: string,
          auth,
          profile
        ) => Promise<any>
      ) => {
        passport.use(
          new Strategy(
            credentials,
            (req, accessToken, refreshToken, profile, done) => {
              callbackify(authHandler)(
                req,
                providerName,
                { accessToken: accessToken, refreshToken: refreshToken },
                profile,
                done
              );
            }
          )
        );
      }
    );
  }

  // Registers a provider that accepts an access_token directly from the client, skipping the popup window and callback
  // This is for supporting Cordova, native IOS and Android apps, as well as other devices
  public registerTokenProvider(providerName: string, Strategy) {
    providerName = providerName.toLowerCase();
    const configRef = 'providers.' + providerName;
    if (this.config.getItem(configRef + '.credentials')) {
      const credentials = this.config.getItem(configRef + '.credentials');
      credentials.passReqToCallback = true;
      const options = this.config.getItem(configRef + '.options') || {};
      // Configure the Passport Strategy
      this.passport.use(
        providerName + '-token',
        new Strategy(
          credentials,
          (req, accessToken, refreshToken, profile, done) => {
            callbackify(this.authHandler)(
              req,
              providerName,
              { accessToken: accessToken, refreshToken: refreshToken },
              profile,
              done
            );
          }
        )
      );
      this.router.post(
        '/' + providerName + '/token',
        this.passportTokenCallback(providerName, options),
        this.initTokenSession.bind(this),
        this.tokenAuthErrorHandler
      );
      if (!this.config.getItem('security.disableLinkAccounts')) {
        this.router.post(
          '/link/' + providerName + '/token',
          this.passport.authenticate('bearer', { session: false }),
          this.passportTokenCallback(providerName, options),
          this.linkTokenSuccess.bind(this),
          this.tokenAuthErrorHandler
        );
      }
      console.log(providerName + '-token loaded.');
    }
  }

  // This is called after a user has successfully authenticated with a provider
  // If a user is authenticated with a bearer token we will link an account, otherwise log in
  // auth is an object containing 'access_token' and optionally 'refresh_token'
  private authHandler(req: SlRequest, provider: string, auth, profile) {
    if (req.user && req.user._id && req.user.key) {
      return this.user.linkSocial(req.user._id, provider, auth, profile, req);
    } else {
      return this.user.socialAuth(provider, auth, profile, req);
    }
  }

  // Configures the passport.authenticate for the given provider, passing in options
  // Operation is 'login' or 'link'
  private passportCallback(provider: string, options, operation) {
    return (req: Request, res: Response, next: NextFunction) => {
      const theOptions = { ...options };
      if (provider === 'linkedin') {
        theOptions.state = true;
      }
      const accessToken = req.query.bearer_token || req.query.state;
      if (
        accessToken &&
        (OAuth.stateRequired.indexOf(provider) > -1 ||
          this.config.getItem('providers.' + provider + '.stateRequired') ===
            true)
      ) {
        theOptions.state = accessToken;
      }
      theOptions.callbackURL = this.getLinkCallbackURLs(
        provider,
        req,
        operation,
        accessToken
      );
      theOptions.session = false;
      this.passport.authenticate(provider, theOptions)(req, res, next);
    };
  }

  // Configures the passport.authenticate for the given access_token provider, passing in options
  private passportTokenCallback(provider: string, options) {
    return (req: Request, res: Response, next: NextFunction) => {
      const theOptions = { ...options };
      theOptions.session = false;
      this.passport.authenticate(provider + '-token', theOptions)(
        req,
        res,
        next
      );
    };
  }

  private getLinkCallbackURLs(
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
        (OAuth.stateRequired.indexOf(provider) > -1 ||
          this.config.getItem('providers.' + provider + '.stateRequired') ===
            true)
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
  private getProvider(pathname: string) {
    const items = pathname.split('/');
    const index = items.indexOf('callback');
    if (index > 0) {
      return items[index - 1];
    }
  }

  /** Gets the provider name from a callback path for access_token strategy */
  private getProviderToken(pathname: string) {
    const items = pathname.split('/');
    const index = items.indexOf('token');
    if (index > 0) {
      return items[index - 1];
    }
  }
}
