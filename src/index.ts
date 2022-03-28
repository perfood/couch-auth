'use strict';
import events from 'events';
import express, { Router } from 'express';
import nano, { DocumentScope, ServerScope } from 'nano';
import { Authenticator } from 'passport';
import { ConfigHelper } from './config/configure';
import seed from './design/seed';
import localConfig from './local';
import { Mailer } from './mailer';
import { Middleware } from './middleware';
import { OAuth } from './oauth';
import loadRoutes from './routes';
import { Config } from './types/config';
import { CouchDbAuthDoc, SlUserDoc } from './types/typings';
import { User } from './user';
import { addProvidersToDesignDoc } from './util';

export class SuperLogin extends User {
  router: Router;
  passport: Authenticator;
  registerProvider: OAuth['registerProvider'];
  registerOAuth2: OAuth['registerOAuth2'];
  registerTokenProvider: OAuth['registerTokenProvider'];
  sendEmail: Mailer['sendEmail'];
  requireAuth: Middleware['requireAuth'];
  requireRole: Middleware['requireRole'];
  requireAnyRole: Middleware['requireAnyRole'];
  requireAllRoles: Middleware['requireAllRoles'];

  constructor(
    configData: Partial<Config>,
    couchServer?: ServerScope,
    passport?: Authenticator
  ) {
    const configHelper = new ConfigHelper(configData);
    const config = configHelper.config;
    const router = express.Router();
    const emitter = new events.EventEmitter();

    if (!passport || typeof passport !== 'object') {
      passport = require('passport');
    }
    const middleware = new Middleware(passport);

    if (!couchServer) {
      couchServer = nano({
        url: config.dbServer.protocol + config.dbServer.host,
        parseUrl: false,
        requestDefaults: {
          auth: {
            username: config.dbServer.user,
            password: config.dbServer.password
          }
        }
      });
    }

    const userDB: DocumentScope<SlUserDoc> = couchServer.use(
      config.dbServer.userDB
    );
    const couchAuthDB: DocumentScope<CouchDbAuthDoc> = couchServer.use(
      config.dbServer.couchAuthDB
    );

    const mailer = new Mailer(config);
    super(config, userDB, couchAuthDB, mailer, emitter, couchServer);
    const oauth = new OAuth(router, passport, this, config);

    // Seed design docs for the user database
    let userDesign = require('./design/user-design');
    userDesign = addProvidersToDesignDoc(config, userDesign);
    seed(userDB, userDesign);
    // Configure Passport local login and api keys
    localConfig(config, passport, this);
    // Load the routes
    loadRoutes(config, router, passport, this);

    this.router = router;
    this.passport = passport;

    this.registerProvider = oauth.registerProvider.bind(oauth);
    this.registerOAuth2 = oauth.registerOAuth2.bind(oauth);
    this.registerTokenProvider = oauth.registerTokenProvider.bind(oauth);

    this.sendEmail = mailer.sendEmail.bind(mailer);

    this.requireAuth = middleware.requireAuth.bind(middleware);
    this.requireRole = middleware.requireRole.bind(middleware);
    this.requireAnyRole = middleware.requireAnyRole.bind(middleware);
    this.requireAllRoles = middleware.requireAllRoles.bind(middleware);
  }

  private async init() {}
}
