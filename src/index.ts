'use strict';
import {
  addProvidersToDesignDoc,
  getCloudantURL,
  getDBURL,
  hashPassword,
  loadCouchServer,
  verifyPassword
} from './util';
import cloudant, { ServerScope as CloudantServer } from '@cloudant/cloudant';
import { CouchDbAuthDoc, SlUserDoc } from './types/typings';
import express, { Router } from 'express';
import nano, { DocumentScope, ServerScope as NanoServer } from 'nano';
import { Authenticator } from 'passport';
import { Config } from './types/config';
import { ConfigHelper } from './config/configure';
import events from 'events';
import { Mailer } from './mailer';
import { Middleware } from './middleware';
import { OAuth } from './oauth';
import seed from './design/seed';
import { User } from './user';

const loadRoutes = require('./routes');
const localConfig = require('./local');

export class SuperLogin extends User {
  router: Router;
  passport: Authenticator;
  couchAuthDB: DocumentScope<CouchDbAuthDoc>;
  registerProvider: OAuth['registerProvider'];
  registerOAuth2: OAuth['registerOAuth2'];
  registerTokenProvider: OAuth['registerTokenProvider'];
  hashPassword: typeof hashPassword;
  verifyPassword: typeof verifyPassword;
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
    const config = new ConfigHelper(
      configData,
      require('./config/default.config')
    );
    const router = express.Router();
    const emitter = new events.EventEmitter();

    if (!passport || typeof passport !== 'object') {
      passport = require('passport');
    }
    const middleware = new Middleware(passport);

    // Some extra default settings if no config object is specified
    if (!configData) {
      config.setItem('testMode.noEmail', true);
      config.setItem('testMode.debugEmail', true);
    }

    // Create the DBs if they weren't passed in
    let server: CloudantServer | NanoServer;
    if (
      (!userDB && config.getItem('dbServer.userDB')) ||
      (!couchAuthDB &&
        config.getItem('dbServer.couchAuthDB') &&
        !config.getItem('dbServer.cloudant'))
    ) {
      server = loadCouchServer(config.config);
    }

    if (!userDB && config.getItem('dbServer.userDB')) {
      userDB = server.use(config.getItem('dbServer.userDB'));
    }
    if (
      !couchAuthDB &&
      config.getItem('dbServer.couchAuthDB') &&
      !config.getItem('dbServer.cloudant')
    ) {
      couchAuthDB = server.use(config.getItem('dbServer.couchAuthDB'));
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

    this.hashPassword = hashPassword;
    this.verifyPassword = verifyPassword;

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
