'use strict';
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const events_1 = __importDefault(require("events"));
const express_1 = __importDefault(require("express"));
const seed_1 = __importDefault(require("./design/seed"));
const nano_1 = __importDefault(require("nano"));
const configure_1 = require("./config/configure");
const user_1 = require("./user");
const Oauth = require('./oauth');
const loadRoutes = require('./routes');
const localConfig = require('./local');
const middleware_1 = require("./middleware");
const mailer_1 = require("./mailer");
const util_1 = require("./util");
//import { PassportStatic } from 'passport';
class SuperLogin extends user_1.User {
    constructor(configData, passport, userDB, couchAuthDB) {
        const config = new configure_1.ConfigHelper(configData, require('./config/default.config'));
        const router = express_1.default.Router();
        const emitter = new events_1.default.EventEmitter();
        if (!passport || typeof passport !== 'object') {
            passport = require('passport');
        }
        const middleware = new middleware_1.Middleware(passport);
        // Some extra default settings if no config object is specified
        if (!configData) {
            config.setItem('testMode.noEmail', true);
            config.setItem('testMode.debugEmail', true);
        }
        // Create the DBs if they weren't passed in
        if (!userDB && config.getItem('dbServer.userDB')) {
            userDB = nano_1.default({
                url: util_1.getDBURL(config.getItem('dbServer')),
                parseUrl: false
            }).use(config.getItem('dbServer.userDB'));
        }
        if (!couchAuthDB &&
            config.getItem('dbServer.couchAuthDB') &&
            !config.getItem('dbServer.cloudant')) {
            couchAuthDB = nano_1.default({
                url: util_1.getDBURL(config.getItem('dbServer')),
                parseUrl: false
            }).use(config.getItem('dbServer.couchAuthDB'));
        }
        if (!userDB || typeof userDB !== 'object') {
            throw new Error('userDB must be passed in as the third argument or specified in the config file under dbServer.userDB');
        }
        const mailer = new mailer_1.Mailer(config);
        super(config, userDB, couchAuthDB, mailer, emitter);
        const oauth = Oauth(router, passport, this, config);
        // Seed design docs for the user database
        let userDesign = require('./design/user-design');
        userDesign = util_1.addProvidersToDesignDoc(config, userDesign);
        seed_1.default(userDB, userDesign);
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
        this.hashPassword = util_1.hashPassword;
        this.verifyPassword = util_1.verifyPassword;
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
