'use strict';
import { addProvidersToDesignDoc, loadCouchServer } from './util';
import { CouchDbAuthDoc, SlUserDoc } from './types/typings';
import { DocumentScope, ServerScope as NanoServer } from 'nano';
import express, { Router } from 'express';
import { Authenticator } from 'passport';
import { ServerScope as CloudantServer } from '@cloudant/cloudant';
import { Config } from './types/config';
import { ConfigHelper } from './config/configure';
import events from 'events';
import loadRoutes from './routes';
import localConfig from './local';
import { Mailer } from './mailer';
import { Middleware } from './middleware';
import { OAuth } from './oauth';
import seed from './design/seed';
import { User } from './user';

export class SuperLogin extends User {
  router: Router;
  passport: Authenticator;
  couchAuthDB: DocumentScope<CouchDbAuthDoc>;
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
    passport?: Authenticator,
    userDB?: DocumentScope<SlUserDoc>,
    couchAuthDB?: DocumentScope<CouchDbAuthDoc>
  ) {
    const configHelper = new ConfigHelper(configData);
    const config = configHelper.config;
    const router = express.Router();
    const emitter = new events.EventEmitter();

    if (!passport || typeof passport !== 'object') {
      passport = require('passport');
    }
    const middleware = new Middleware(passport);

    // Create the DBs if they weren't passed in
    let server: CloudantServer | NanoServer;
    if (
      (!userDB && config.dbServer.userDB) ||
      (!couchAuthDB && config.dbServer.couchAuthDB && !config.dbServer.cloudant)
    ) {
      server = loadCouchServer(config);
    }

    if (!userDB && config.dbServer.userDB) {
      userDB = server.use(config.dbServer.userDB);
    }
    if (
      !couchAuthDB &&
      config.dbServer.couchAuthDB &&
      !config.dbServer.cloudant
    ) {
      couchAuthDB = server.use(config.dbServer.couchAuthDB);
    }
    if (!userDB || typeof userDB !== 'object') {
      throw new Error(
        'userDB must be passed in as the third argument or specified in the config file under dbServer.userDB'
      );
    }

    const mailer = new Mailer(config);
    super(config, userDB, couchAuthDB, mailer, emitter);
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
    this.couchAuthDB = couchAuthDB;

    this.registerProvider = oauth.registerProvider.bind(oauth);
    this.registerOAuth2 = oauth.registerOAuth2.bind(oauth);
    this.registerTokenProvider = oauth.registerTokenProvider.bind(oauth);

    this.sendEmail = mailer.sendEmail.bind(mailer);

    this.requireAuth = middleware.requireAuth.bind(middleware);
    this.requireRole = middleware.requireRole.bind(middleware);
    this.requireAnyRole = middleware.requireAnyRole.bind(middleware);
    this.requireAllRoles = middleware.requireAllRoles.bind(middleware);

    // Inherit emitter
    for (const key in emitter) {
      this[key] = emitter[key];
    }
  }
}

module.exports = SuperLogin;
