'use strict';
var events = require('events');
var express = require('express');
var PouchDB = require('pouchdb');
var seed = require('pouchdb-seed-design');

var Configure = require('./configure');
var User = require('./user');
var Oauth = require('./oauth');
var loadRoutes = require('./routes');
var localConfig = require('./local');
var Middleware = require('./middleware');
var Mailer = require('./mailer');
var util = require('./util');

class SuperLogin extends User {
  constructor(configData, passport, userDB, couchAuthDB) {
    var config = new Configure(configData, require('../config/default.config'));
    var router = express.Router();
    var emitter = new events.EventEmitter();

    if (!passport || typeof passport !== 'object') {
      passport = require('passport');
    }
    var middleware = new Middleware(passport);

    // Some extra default settings if no config object is specified
    if (!configData) {
      config.setItem('testMode.noEmail', true);
      config.setItem('testMode.debugEmail', true);
    }

    // Create the DBs if they weren't passed in
    if (!userDB && config.getItem('dbServer.userDB')) {
      userDB = new PouchDB(
        util.getFullDBURL(
          config.getItem('dbServer'),
          config.getItem('dbServer.userDB')
        )
      );
    }
    if (
      !couchAuthDB &&
      config.getItem('dbServer.couchAuthDB') &&
      !config.getItem('dbServer.cloudant')
    ) {
      couchAuthDB = new PouchDB(
        util.getFullDBURL(
          config.getItem('dbServer'),
          config.getItem('dbServer.couchAuthDB')
        )
      );
    }
    if (!userDB || typeof userDB !== 'object') {
      throw new Error(
        'userDB must be passed in as the third argument or specified in the config file under dbServer.userDB'
      );
    }

    var mailer = new Mailer(config);
    super(config, userDB, couchAuthDB, mailer, emitter);
    var oauth = Oauth(router, passport, this, config);

    // Seed design docs for the user database
    var userDesign = require('../designDocs/user-design');
    userDesign = util.addProvidersToDesignDoc(config, userDesign);
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

    this.registerProvider = oauth.registerProvider;
    this.registerOAuth2 = oauth.registerOAuth2;
    this.registerTokenProvider = oauth.registerTokenProvider;

    this.hashPassword = util.hashPassword;
    this.verifyPassword = util.verifyPassword;

    this.sendEmail = mailer.sendEmail;

    this.requireAuth = middleware.requireAuth;
    this.requireRole = middleware.requireRole;
    this.requireAnyRole = middleware.requireAnyRole;
    this.requireAllRoles = middleware.requireAllRoles;

    // Inherit emitter
    for (var key in emitter) {
      this[key] = emitter[key];
    }
  }
}

module.exports = SuperLogin;
