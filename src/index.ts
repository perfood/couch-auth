'use strict';
import events from 'events';
import express, { Router } from 'express';
import seed from './design/seed';
import nano, { DocumentScope } from 'nano';

import { ConfigHelper } from './config/configure';
import { User } from './user';
const Oauth = require('./oauth');
const loadRoutes = require('./routes');
const localConfig = require('./local');
import { Middleware } from './middleware';
import { Mailer } from './mailer';
import {
  getDBURL,
  hashPassword,
  verifyPassword,
  addProvidersToDesignDoc
} from './util';
import { Config } from 'config';
import { Authenticator } from 'passport';
//import { PassportStatic } from 'passport';

export class SuperLogin extends User {
  router: Router;
  mailer: Mailer;
  passport: any;
  couchAuthDB: DocumentScope<any>;
  registerProvider: Function;
  registerOAuth2: Function;
  registerTokenProvider: Function;
  hashPassword: Function;
  verifyPassword: Function;
  sendEmail: Function;
  requireAuth: Function;
  requireRole: Function;
  requireAnyRole: Function;
  requireAllRoles: Function;

  constructor(
    configData: Partial<Config>,
    passport: Authenticator,
    userDB: DocumentScope<any>,
    couchAuthDB: DocumentScope<any>
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
    if (!userDB && config.getItem('dbServer.userDB')) {
      userDB = nano({
        url: getDBURL(config.getItem('dbServer')),
        parseUrl: false
      }).use(config.getItem('dbServer.userDB'));
    }
    if (
      !couchAuthDB &&
      config.getItem('dbServer.couchAuthDB') &&
      !config.getItem('dbServer.cloudant')
    ) {
      couchAuthDB = nano({
        url: getDBURL(config.getItem('dbServer')),
        parseUrl: false
      }).use(config.getItem('dbServer.couchAuthDB'));
    }
    if (!userDB || typeof userDB !== 'object') {
      throw new Error(
        'userDB must be passed in as the third argument or specified in the config file under dbServer.userDB'
      );
    }

    const mailer = new Mailer(config);
    super(config, userDB, couchAuthDB, mailer, emitter);
    const oauth = Oauth(router, passport, this, config);

    // Seed design docs for the user database
    let userDesign = require('./design/user-design');
    userDesign = addProvidersToDesignDoc(config, userDesign);
    seed(userDB, userDesign);
    // Configure Passport local login and api keys
    localConfig(config, passport, this);
    // Load the routes
    loadRoutes(config, router, passport, this);

    this.config = config;
    this.router = router;
    this.mailer = mailer;
    this.passport = passport;
    this.userDB = userDB;
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
