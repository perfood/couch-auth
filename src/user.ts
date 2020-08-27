'use strict';
import {
  arrayUnion,
  EMAIL_REGEXP,
  getExpiredSessions,
  getSessions,
  hashToken,
  hyphenizeUUID,
  removeHyphens,
  URLSafeUUID,
  USER_REGEXP
} from './util';
import {
  CouchDbAuthDoc,
  HashResult,
  LocalHashObj,
  SessionObj,
  SlLoginSession,
  SlRefreshSession,
  SlRequest,
  SlUserDoc,
  SlUserNew
} from './types/typings';
import Model, { Sofa } from '@sl-nx/sofa-model';
import { Config } from './types/config';
import { DBAuth } from './dbauth';
import { DbManager } from './user/DbManager';
import { DocumentScope } from 'nano';
import { EventEmitter } from 'events';
import { Hashing } from './hashing';
import { Mailer } from './mailer';
import merge from 'deepmerge';
import { Request } from 'express';
import { Session } from './session';
import url from 'url';
import { v4 as uuidv4 } from 'uuid';

enum Cleanup {
  'expired' = 'expired',
  'other' = 'other',
  'all' = 'all'
}
enum ValidErr {
  'exists' = 'already in use',
  'emailInvalid' = 'invalid email',
  'userInvalid' = 'invalid username'
}

export class User {
  private dbAuth: DBAuth;
  private userDbManager: DbManager;
  private session: Session;
  private onCreateActions;
  private onLinkActions;
  private hasher: Hashing;

  passwordConstraints;
  // validation funs. todo: implement via bind...
  validateUsername: Function;
  validateEmail: Function;

  userModel: Sofa.AsyncOptions;
  resetPasswordModel: Sofa.AsyncOptions;
  changePasswordModel: Sofa.AsyncOptions;

  constructor(
    protected config: Partial<Config>,
    protected userDB: DocumentScope<SlUserDoc>,
    couchAuthDB: DocumentScope<CouchDbAuthDoc>,
    protected mailer: Mailer,
    protected emitter: EventEmitter
  ) {
    this.dbAuth = new DBAuth(config, userDB, couchAuthDB);
    this.onCreateActions = [];
    this.onLinkActions = [];
    this.hasher = new Hashing(config);
    this.session = new Session(this.hasher);
    this.userDbManager = new DbManager(userDB, config);

    // Token valid for 24 hours by default
    // Session token life
    this.passwordConstraints = {
      presence: true,
      length: {
        minimum: 6,
        message: 'must be at least 6 characters'
      },
      matches: 'confirmPassword'
    };
    const additionalConstraints = config.local.passwordConstraints;
    this.passwordConstraints = merge(
      this.passwordConstraints,
      additionalConstraints ? additionalConstraints : {}
    );

    // the validation functions are public
    this.validateUsername = async function (username) {
      if (!username) {
        return;
      }
      if (username.startsWith('_') || !username.match(USER_REGEXP)) {
        return ValidErr.userInvalid;
      }
      try {
        const result = await userDB.view('auth', 'key', { key: username });
        if (result.rows.length === 0) {
          // Pass!
          return;
        } else {
          return ValidErr.exists;
        }
      } catch (err) {
        throw new Error(err);
      }
    };

    this.validateEmail = async function (email): Promise<string | void> {
      if (!email) {
        return;
      }
      if (!email.match(EMAIL_REGEXP)) {
        return ValidErr.emailInvalid;
      }
      try {
        const result = await userDB.view('auth', 'email', { key: email });
        if (result.rows.length === 0) {
          // Pass!
          return;
        } else {
          return ValidErr.exists;
        }
      } catch (err) {
        throw new Error(err);
      }
    };

    // SofaModelOptions
    const userModel: Sofa.AsyncOptions = {
      async: true,
      whitelist: ['name', 'username', 'email', 'password', 'confirmPassword'],
      customValidators: {
        validateEmail: this.validateEmail,
        validateUsername: this.validateUsername,
        matches: this.matches
      },
      sanitize: {
        name: ['trim'],
        username: ['trim', 'toLowerCase'],
        email: ['trim', 'toLowerCase']
      },
      validate: {
        email: {
          presence: true,
          validateEmail: true
        },
        username: {
          presence: true,
          validateUsername: true
        },
        password: this.passwordConstraints,
        confirmPassword: {
          presence: true
        }
      },
      static: {
        type: 'user',
        roles: config.security.defaultRoles,
        providers: ['local']
      },
      rename: {
        username: 'key'
      }
    };

    if (this.config.local.emailUsername) {
      delete userModel.validate.username;
    }
    this.userModel = userModel;

    this.resetPasswordModel = {
      async: true,
      customValidators: {
        matches: this.matches
      },
      validate: {
        token: {
          presence: true
        },
        password: this.passwordConstraints,
        confirmPassword: {
          presence: true
        }
      }
    };

    this.changePasswordModel = {
      async: true,
      customValidators: {
        matches: this.matches
      },
      validate: {
        newPassword: this.passwordConstraints,
        confirmPassword: {
          presence: true
        }
      }
    };
  }

  hashPassword(pw: string): Promise<HashResult> {
    return this.hasher.hashUserPassword(pw);
  }
  verifyPassword(obj: LocalHashObj, pw: string): Promise<boolean> {
    return this.hasher.verifyUserPassword(obj, pw);
  }

  /**
   * Use this to add as many functions as you want to transform the new user document before it is saved.
   * Your function should accept two arguments (userDoc, provider) and return a Promise that resolves to the modified user document.
   * onCreate functions will be chained in the order they were added.
   * @param {Function} fn
   */
  onCreate(fn) {
    if (typeof fn === 'function') {
      this.onCreateActions.push(fn);
    } else {
      throw new TypeError('onCreate: You must pass in a function');
    }
  }

  /**
   * Does the same thing as onCreate, but is called every time a user links a new provider, or their profile information is refreshed.
   * This allows you to process profile information and, for example, create a master profile.
   * If an object called profile exists inside the user doc it will be passed to the client along with session information at each login.
   * @param {Function} fn
   */
  onLink(fn) {
    if (typeof fn === 'function') {
      this.onLinkActions.push(fn);
    } else {
      throw new TypeError('onLink: You must pass in a function');
    }
  }

  /** Validation function for ensuring that two fields match */
  matches(value, option, key, attributes) {
    if (attributes && attributes[option] !== value) {
      return 'does not match ' + option;
    }
  }

  processTransformations(fnArray, userDoc, provider) {
    let promise;
    fnArray.forEach(fn => {
      if (!promise) {
        promise = fn.call(null, userDoc, provider);
      } else {
        if (!promise.then || typeof promise.then !== 'function') {
          throw new Error('onCreate function must return a promise');
        }
        promise.then(newUserDoc => {
          return fn.call(null, newUserDoc, provider);
        });
      }
    });
    if (!promise) {
      promise = Promise.resolve(userDoc);
    }
    return promise;
  }

  /**
   * retrieves by email (default) or username or uuid if the config options are
   * set. Rejects if no valid format.
   */
  getUser(login: string): Promise<SlUserDoc | null> {
    return this.userDbManager.getUser(login);
  }

  async handleEmailExists(email: string): Promise<void> {
    const existingUser = await this.userDbManager.getUserBy('email', email);
    await this.mailer.sendEmail('signupExistingEmail', email, {
      user: existingUser
    });
    this.emitter.emit('signup-attempt', existingUser, 'local');
  }

  async createUser(form, req = undefined): Promise<void | SlUserDoc> {
    req = req || {};
    let finalUserModel = this.userModel;
    const newUserModel = this.config.userModel;
    if (typeof newUserModel === 'object') {
      let whitelist;
      if (newUserModel.whitelist) {
        whitelist = arrayUnion(
          this.userModel.whitelist,
          newUserModel.whitelist
        );
      }
      const addUserModel = this.config.userModel;
      finalUserModel = merge(
        this.userModel,
        addUserModel ? (addUserModel as Sofa.AsyncOptions) : {}
      );
      finalUserModel.whitelist = whitelist || finalUserModel.whitelist;
    }
    const UserModel = Model(finalUserModel);
    const user = new UserModel(form);
    let newUser: Partial<SlUserNew>;
    try {
      newUser = await user.process();
    } catch (err) {
      if (
        err.email &&
        this.config.local.emailUsername &&
        this.config.local.requireEmailConfirm
      ) {
        const inUseIdx = err.email.findIndex((s: string) =>
          s.endsWith(ValidErr.exists)
        );
        err.email.splice(inUseIdx, 1);
        if (err.email.length === 0 && Object.keys(err).length === 1) {
          return this.handleEmailExists(form.email);
        }
      }
      throw {
        error: 'Validation failed',
        validationErrors: err,
        status: 400
      };
    }
    const uid = uuidv4();
    // todo: remove, this is just for backwards compat...
    if (this.config.local.sendNameAndUUID) {
      newUser.user_uid = uid;
    }
    newUser._id = removeHyphens(uid);
    if (this.config.local.emailUsername) {
      const base = newUser.email.split('@')[0].toLowerCase();
      newUser.key = await this.userDbManager.generateUsername(base);
    }
    if (this.config.local.sendConfirmEmail) {
      newUser.unverifiedEmail = {
        email: newUser.email,
        token: URLSafeUUID()
      };
      delete newUser.email;
    }
    newUser.local = await this.hashPassword(newUser.password);
    delete newUser.password;
    delete newUser.confirmPassword;
    newUser.signUp = {
      provider: 'local',
      timestamp: new Date().toISOString()
    };
    newUser = await this.addUserDBs(newUser as SlUserDoc);
    newUser = await this.userDbManager.logActivity(
      newUser._id,
      'signup',
      'local',
      newUser as SlUserDoc
    );
    const finalNewUser = await this.processTransformations(
      this.onCreateActions,
      newUser,
      'local'
    );
    const result = await this.userDB.insert(finalNewUser);
    newUser._rev = result.rev;
    if (this.config.local.sendConfirmEmail) {
      await this.mailer.sendEmail(
        'confirmEmail',
        newUser.unverifiedEmail.email,
        { req: req, user: newUser }
      );
    }
    this.emitter.emit('signup', newUser, 'local');
    return newUser as SlUserDoc;
  }

  /**
   * Creates a new user following authentication from an OAuth provider.
   * If the user already exists it will update the profile.
   * @param {string} provider the name of the provider in lowercase, (e.g. 'facebook')
   * @param {any} auth credentials supplied by the provider
   * @param {any} profile the profile supplied by the provider
   */
  socialAuth(provider, auth, profile): Promise<SlUserDoc> {
    let user: Partial<SlUserDoc>;
    let newAccount = false;
    let action;
    let baseUsername;
    // This used to be consumed by `.nodeify` from Bluebird. I hope `callbackify` works just as well...
    return Promise.resolve()
      .then(() => {
        return this.userDB.view('auth', provider, {
          key: profile.id,
          include_docs: true
        });
      })
      .then(results => {
        if (results.rows.length > 0) {
          user = results.rows[0].doc;
          return Promise.resolve();
        } else {
          newAccount = true;
          user = {
            email: profile.emails ? profile.emails[0].value : undefined,
            providers: [provider],
            type: 'user',
            roles: this.config.security.defaultRoles,
            signUp: {
              provider: provider,
              timestamp: new Date().toISOString()
            }
          };
          user[provider] = {};

          const emailFail = () => {
            return Promise.reject({
              error: 'Email already in use',
              message:
                'Your email is already in use. Try signing in first and then linking this account.',
              status: 409
            });
          };
          // Now we need to generate a username
          if (!user.email) {
            return Promise.reject({
              error: 'No email provided',
              message: `An email is required for registration, but ${provider} didn't supply one.`,
              status: 400
            });
          }
          if (profile.username) {
            baseUsername = profile.username.toLowerCase();
          } else {
            const parseEmail = user.email.split('@');
            baseUsername = parseEmail[0].toLowerCase();
          }
          return this.validateEmail(user.email).then(err => {
            if (err) {
              return emailFail();
            }
            return Promise.resolve(
              this.userDbManager.generateUsername(baseUsername)
            );
          });
        }
      })
      .then(finalUsername => {
        if (finalUsername) {
          user.key = finalUsername;
        }
        user[provider].auth = auth;
        user[provider].profile = profile;
        if (!user.name) {
          user.name = profile.displayName;
        }
        delete user[provider].profile._raw;
        if (newAccount) {
          user._id = removeHyphens(uuidv4());
          return this.addUserDBs(user as SlUserDoc);
        } else {
          return Promise.resolve(user as SlUserDoc);
        }
      })
      .then(userDoc => {
        action = newAccount ? 'signup' : 'login';
        return this.userDbManager.logActivity(
          userDoc._id,
          action,
          provider,
          userDoc
        );
      })
      .then(userDoc => {
        if (newAccount) {
          return this.processTransformations(
            this.onCreateActions,
            userDoc,
            provider
          );
        } else {
          return this.processTransformations(
            this.onLinkActions,
            userDoc,
            provider
          );
        }
      })
      .then(finalUser => {
        return this.userDB.insert(finalUser);
      })
      .then(() => {
        if (action === 'signup') {
          this.emitter.emit('signup', user, provider);
        }
        return Promise.resolve(user as SlUserDoc);
      });
  }

  async linkSocial(
    login: string,
    provider: string,
    auth,
    profile
  ): Promise<SlUserDoc> {
    const userDoc = await this.userDbManager.initLinkSocial(
      login,
      provider,
      auth,
      profile
    );
    const finalUser = await this.processTransformations(
      this.onLinkActions,
      userDoc,
      provider
    );
    await this.userDB.insert(finalUser);
    return finalUser;
  }

  /**
   * Removes the specified provider from the user's account. Local cannot be removed. If there is only one provider left it will fail.
   * Returns the modified user, if successful.
   * @param {string} user_id
   * @param {string} provider
   */
  unlink(user_id, provider) {
    return this.userDbManager.unlink(user_id, provider);
  }

  /**
   * Creates a new session for a user. provider is the name of the provider. (eg. 'local', 'facebook', twitter.)
   * req is used to log the IP if provided.
   */
  async createSession(
    login: string,
    provider: string,
    byUUID = false
  ): Promise<SlLoginSession> {
    let user = byUUID
      ? await this.userDbManager.getUserByUUID(login)
      : await this.getUser(login);
    if (!user) {
      console.log('createSession - could not retrieve: ', login);
      throw { error: 'Bad Request', status: 400 };
    }
    const user_uid = user._id;
    const token = await this.generateSession(user_uid, user.roles);
    const password = token.password;
    const newToken = token;
    newToken.provider = provider;
    await this.dbAuth.storeKey(
      user.key,
      newToken.key,
      password,
      newToken.expires,
      user.roles,
      provider
    );
    // authorize the new session across all dbs
    if (user.personalDBs) {
      await this.dbAuth.authorizeUserSessions(
        user_uid,
        user.personalDBs,
        newToken.key,
        user.roles
      );
    }
    if (!user.session) {
      user.session = {};
    }
    const newSession: Partial<SlLoginSession> = {
      issued: newToken.issued,
      expires: newToken.expires,
      provider: provider
    };
    user.session[newToken.key] = newSession as SessionObj;
    // Clear any failed login attempts
    if (provider === 'local') {
      if (!user.local) user.local = {};
      user.local.failedLoginAttempts = 0;
      delete user.local.lockedUntil;
    }
    const userDoc = await this.userDbManager.logActivity(
      user_uid,
      'login',
      provider,
      user
    );
    // Clean out expired sessions on login
    const finalUser = await this.logoutUserSessions(userDoc, Cleanup.expired);
    user = finalUser;
    await this.userDB.insert(finalUser);
    newSession.token = newToken.key;
    newSession.password = password;
    newSession.user_id = user.key;
    newSession.roles = user.roles;
    // Inject the list of userDBs
    if (typeof user.personalDBs === 'object') {
      const userDBs = {};
      let publicURL;
      if (this.config.dbServer.publicURL) {
        const dbObj = url.parse(this.config.dbServer.publicURL);
        dbObj.auth = newSession.token + ':' + newSession.password;
        publicURL = url.format(dbObj);
      } else {
        publicURL =
          this.config.dbServer.protocol +
          newSession.token +
          ':' +
          newSession.password +
          '@' +
          this.config.dbServer.host +
          '/';
      }
      Object.keys(user.personalDBs).forEach(finalDBName => {
        userDBs[user.personalDBs[finalDBName].name] = publicURL + finalDBName;
      });
      newSession.userDBs = userDBs;
    }
    if (user.profile) {
      newSession.profile = user.profile;
    }
    if (this.config.local.sendNameAndUUID) {
      if (user.name) {
        newSession.name = user.name;
      }
      newSession.user_uid = hyphenizeUUID(user._id);
    }
    this.emitter.emit('login', newSession, provider);
    return newSession as SlLoginSession;
  }

  /** returns `true` if user is now locked. */
  handleFailedLogin(user: SlUserDoc, req: Partial<Request>): Promise<boolean> {
    return this.userDbManager.handleFailedLogin(user, req);
  }

  /**
   * Extends the life of your current token and returns updated token information.
   * The only field that will change is expires. Expired sessions are removed.
   * todo:
   * - handle error if invalid state occurs that doc is not present.
   */
  async refreshSession(key: string): Promise<SlRefreshSession> {
    const userDoc = await this.userDbManager.findUserDocBySession(key);
    userDoc.session[key].expires =
      Date.now() + this.config.security.sessionLife * 1000;
    // Clean out expired sessions on refresh
    const finalUser = await this.logoutUserSessions(userDoc, Cleanup.expired);
    await this.userDB.insert(finalUser);
    const newSession: SlRefreshSession = {
      ...userDoc.session[key],
      token: key,
      user_uid: hyphenizeUUID(userDoc._id),
      user_id: userDoc.key,
      roles: userDoc.roles
    };
    delete newSession['ip'];
    this.emitter.emit('refresh', newSession);
    return newSession;
  }

  /**
   * Required form fields: token, password, and confirmPassword
   */
  resetPassword(form, req: Partial<Request> = undefined): Promise<SlUserDoc> {
    req = req || {};
    const ResetPasswordModel = Model(this.resetPasswordModel);
    const passwordResetForm = new ResetPasswordModel(form);
    let user: SlUserDoc;
    return passwordResetForm
      .validate()
      .then(
        () => {
          const tokenHash = hashToken(form.token);
          return this.userDB.view('auth', 'passwordReset', {
            key: tokenHash,
            include_docs: true
          });
        },
        err => {
          return Promise.reject({
            error: 'Validation failed',
            validationErrors: err,
            status: 400
          });
        }
      )
      .then(results => {
        if (!results.rows.length) {
          return Promise.reject({ status: 400, error: 'Invalid token' });
        }
        user = results.rows[0].doc;
        if (user.forgotPassword.expires < Date.now()) {
          return Promise.reject({ status: 400, error: 'Token expired' });
        }
        return this.hashPassword(form.password);
      })
      .then(hash => {
        if (!user.local) {
          user.local = {};
        }
        user.local = { ...user.local, ...hash };
        if (user.providers.indexOf('local') === -1) {
          user.providers.push('local');
        }
        // logout user completely
        return this.logoutUserSessions(user, Cleanup.all);
      })
      .then(async userDoc => {
        user = userDoc;
        delete user.forgotPassword;
        if (user.unverifiedEmail) {
          user = await this.markEmailAsVerified(
            user,
            'verified via password reset'
          );
        }
        return this.userDbManager.logActivity(
          user._id,
          'reset password',
          'local',
          user
        );
      })
      .then(finalUser => this.userDB.insert(finalUser))
      .then(() => this.sendModifiedPasswordEmail(user, req))
      .then(() => {
        this.emitter.emit('password-reset', user);
        return Promise.resolve(user);
      });
  }

  async changePasswordSecure(login: string, form, req?) {
    req = req || {};
    const ChangePasswordModel = Model(this.changePasswordModel);
    const changePasswordForm = new ChangePasswordModel(form);
    try {
      await changePasswordForm.validate();
    } catch (err) {
      throw {
        error: 'Validation failed',
        validationErrors: err,
        status: 400
      };
    }

    try {
      const user = await this.getUser(login);
      if (!user) {
        throw { error: 'Bad Request', status: 400 }; // should exist.
      }
      if (user.local && user.local.salt && user.local.derived_key) {
        // Password is required
        if (!form.currentPassword) {
          throw {
            error: 'Password change failed',
            message:
              'You must supply your current password in order to change it.',
            status: 400
          };
        }
        await this.verifyPassword(user.local, form.currentPassword);
      }
      await this.changePassword(user._id, form.newPassword, user, req);
    } catch (err) {
      throw (
        err || {
          error: 'Password change failed',
          message: 'The current password you supplied is incorrect.',
          status: 400
        }
      );
    }
    if (req.user && req.user.key) {
      return this.logoutOthers(req.user.key);
    } else {
      return;
    }
  }

  forgotUsername(email: string, req: Partial<Request>) {
    if (!email || !email.match(EMAIL_REGEXP)) {
      return Promise.reject({ error: 'invalid email', status: 400 });
    }
    req = req || {};
    let user: SlUserDoc;
    return this.userDbManager
      .getUserBy('email', email)
      .then(user => {
        if (!user) {
          return Promise.reject({
            error: 'User not found',
            status: 404
          });
        }
      })
      .then(() => {
        return this.mailer.sendEmail(
          'forgotUsername',
          user.email || user.unverifiedEmail.email,
          { user: user, req: req }
        );
      })
      .then(() => {
        this.emitter.emit('forgot-username', user);
        return Promise.resolve(user);
      })
      .catch(err => {
        this.emitter.emit('forgot-username-attempt', email);
        if (err.status === 404) {
          return Promise.resolve();
        } else {
          return Promise.reject(err);
        }
      });
  }

  async changePassword(
    user_id: string,
    newPassword: string,
    userDoc: SlUserDoc,
    req
  ) {
    req = req || {};
    if (!userDoc) {
      try {
        userDoc = await this.userDB.get(user_id);
      } catch (error) {
        throw {
          error: 'User not found',
          status: 404
        };
      }
    }
    const hash = await this.hashPassword(newPassword);
    if (!userDoc.local) {
      userDoc.local = {};
    }
    if (userDoc.providers.indexOf('local') === -1) {
      userDoc.providers.push('local');
    }
    userDoc.local = { ...userDoc.local, ...hash };
    const finalUser = await this.userDbManager.logActivity(
      userDoc._id,
      'changed password',
      'local',
      userDoc
    );
    await this.userDB.insert(finalUser);
    await this.sendModifiedPasswordEmail(userDoc, req);
    this.emitter.emit('password-change', userDoc);
  }

  private sendModifiedPasswordEmail(user, req) {
    if (this.config.local.sendPasswordChangedEmail) {
      return this.mailer.sendEmail(
        'modifiedPassword',
        user.email || user.unverifiedEmail.email,
        { user: user, req: req }
      );
    } else {
      return Promise.resolve();
    }
  }

  forgotPassword(email: string, req: Partial<Request>) {
    if (!email || !email.match(EMAIL_REGEXP)) {
      return Promise.reject({ error: 'invalid email', status: 400 });
    }
    req = req || {};
    let user: SlUserDoc, token, tokenHash;
    return this.userDbManager
      .getUserBy('email', email)
      .then(res => {
        if (!res) {
          return Promise.reject({
            error: 'User not found',
            status: 404
          });
        }
        user = res;
        token = URLSafeUUID();
        if (this.config.local.tokenLengthOnReset) {
          token = token.substring(0, this.config.local.tokenLengthOnReset);
        }
        tokenHash = hashToken(token);
        user.forgotPassword = {
          token: tokenHash, // Store secure hashed token
          issued: Date.now(),
          expires: Date.now() + this.config.security.tokenLife * 1000
        };
        return this.userDbManager.logActivity(
          user._id,
          'forgot password',
          'local',
          user
        );
      })
      .then(finalUser => {
        return this.userDB.insert(finalUser);
      })
      .then(() => {
        return this.mailer.sendEmail(
          'forgotPassword',
          user.email || user.unverifiedEmail.email,
          { user: user, req: req, token: token }
        );
      })
      .then(() => {
        this.emitter.emit('forgot-password', user);
        return Promise.resolve(user.forgotPassword);
      })
      .catch(err => {
        this.emitter.emit('forgot-password-attempt', email);
        if (err.status === 404) {
          return Promise.resolve();
        } else {
          return Promise.reject(err);
        }
      });
  }

  verifyEmail(token: string) {
    let user: SlUserDoc;
    return this.userDB
      .view('auth', 'verifyEmail', { key: token, include_docs: true })
      .then(result => {
        if (!result.rows.length) {
          return Promise.reject({ error: 'Invalid token', status: 400 });
        }
        user = result.rows[0].doc;
        return this.markEmailAsVerified(user, 'verified email');
      })
      .then(finalUser => {
        return this.userDB.insert(finalUser);
      });
  }

  private async markEmailAsVerified(userDoc, logInfo) {
    userDoc.email = userDoc.unverifiedEmail.email;
    delete userDoc.unverifiedEmail;
    this.emitter.emit('email-verified', userDoc);
    return await this.userDbManager.logActivity(
      userDoc.key,
      logInfo,
      'local',
      userDoc
    );
  }

  async changeEmail(login: string, newEmail: string, req: Partial<SlRequest>) {
    req = req || {};
    if (!req.user) {
      req.user = { provider: 'local' };
    }
    const emailError = await this.validateEmail(newEmail);
    if (emailError) {
      if (
        this.config.local.requireEmailConfirm &&
        emailError === ValidErr.exists
      ) {
        this.emitter.emit('illegal-email-change', login, newEmail);
        return;
      } else {
        throw emailError;
      }
    }
    const user = await this.getUser(login);
    if (!user) {
      throw { error: 'Bad Request', status: 400 }; // should exist.
    }
    if (this.config.local.sendConfirmEmail) {
      user.unverifiedEmail = {
        email: newEmail,
        token: URLSafeUUID()
      };
      const mailType = this.config.emails.confirmEmailChange
        ? 'confirmEmailChange'
        : 'confirmEmail';
      await this.mailer.sendEmail(mailType, user.unverifiedEmail.email, {
        req: req,
        user: user
      });
    } else {
      user.email = newEmail;
    }
    this.emitter.emit('email-changed', user);
    const finalUser = await this.userDbManager.logActivity(
      user._id,
      'changed email',
      req.user.provider,
      user
    );
    return this.userDB.insert(finalUser);
  }

  async removeUserDB(
    login: string,
    dbName: string,
    deletePrivate,
    deleteShared
  ) {
    let update = false;
    const user = await this.getUser(login);
    if (!user) {
      throw { status: 404, error: 'User not found' };
    }
    if (user.personalDBs && typeof user.personalDBs === 'object') {
      for (const db of Object.keys(user.personalDBs)) {
        if (user.personalDBs[db].name === dbName) {
          const type = user.personalDBs[db].type;
          delete user.personalDBs[db];
          update = true;
          if (type === 'private' && deletePrivate) {
            await this.dbAuth.removeDB(dbName);
          }
          if (type === 'shared' && deleteShared) {
            await this.dbAuth.removeDB(dbName);
          }
        }
      }
    }
    if (update) {
      this.emitter.emit('user-db-removed', user.key, dbName);
      return this.userDB.insert(user);
    }
  }

  /**
   * Logs out a user either by his provided login information (uuid, email or
   * username) or his session_id
   */
  async logoutUser(login: string, session_id: string) {
    let user: SlUserDoc;
    if (login) {
      user = await this.getUser(login);
    } else if (session_id) {
      user = await this.userDbManager.findUserDocBySession(session_id);
    }
    if (!user) {
      return Promise.reject({
        error: 'unauthorized',
        status: 401
      });
    }
    await this.logoutUserSessions(user, Cleanup.all);
    this.emitter.emit('logout', user.key);
    this.emitter.emit('logout-all', user.key);
    return this.userDB.insert(user);
  }

  /**
   * todo: Should I really allow to fail after `removeKeys`?
   * -> I'd like my `sl-users` to be single source of truth, don't I?
   */
  async logoutSession(session_id: string) {
    let startSessions = 0;
    let endSessions = 0;
    let user = await this.userDbManager.findUserDocBySession(session_id);
    if (!user) {
      throw {
        error: 'unauthorized',
        status: 401
      };
    }
    if (user.session) {
      startSessions = Object.keys(user.session).length;
      if (user.session[session_id]) {
        delete user.session[session_id];
      }
    }
    // 1.) if this fails, the whole logout has failed! Else ok, will be cleaned up later.
    await this.dbAuth.removeKeys(session_id);
    //console.log('1.) - removed keys for', session_id);
    let caughtError = {};
    try {
      // 2) deauthorize from user's dbs
      await this.dbAuth.deauthorizeUser(user, session_id);
      //console.log('2.) - deauthorized user for ', session_id);

      // Clean out expired sessions
      user = await this.logoutUserSessions(user, Cleanup.expired);
      //console.log('3.) - cleaned up for user', user.key);
      if (user.session) {
        endSessions = Object.keys(user.session).length;
      }
      this.emitter.emit('logout', user.key);
      if (startSessions !== endSessions) {
        // 3) update the sl-doc
        return this.userDB.insert(user);
      } else {
        return false;
      }
    } catch (error) {
      caughtError = {
        err: error.err,
        reason: error.reason,
        statusCode: error.statusCode
      };
      console.warn(
        'Error during logoutSessions() - err: ' +
          error.err +
          ', reason: ' +
          error.reason +
          ', status: ' +
          error.statusCode
      );
    }
    return caughtError;
  }

  async logoutOthers(session_id) {
    const user = await this.userDbManager.findUserDocBySession(session_id);
    if (user) {
      if (user.session && user.session[session_id]) {
        const finalUser = await this.logoutUserSessions(
          user,
          Cleanup.other,
          session_id
        );
        return this.userDB.insert(finalUser);
      }
    }
    return false;
  }

  async logoutUserSessions(
    userDoc: SlUserDoc,
    op: Cleanup,
    currentSession?: string
  ) {
    // When op is 'other' it will logout all sessions except for the specified 'currentSession'
    let sessions;
    if (op === Cleanup.all || op === Cleanup.other) {
      sessions = getSessions(userDoc);
    } else if (op === Cleanup.expired) {
      sessions = getExpiredSessions(userDoc, Date.now());
    }
    if (op === Cleanup.other && currentSession) {
      // Remove the current session from the list of sessions we are going to delete
      const index = sessions.indexOf(currentSession);
      if (index > -1) {
        sessions.splice(index, 1);
      }
    }
    if (sessions.length) {
      // 1.) Remove the keys from our couchDB auth database. Must happen first.
      await this.dbAuth.removeKeys(sessions);
      // 2.) Deauthorize keys from each personal database and from session store
      await this.dbAuth.deauthorizeUser(userDoc, sessions);
      if (op === Cleanup.expired || op === Cleanup.other) {
        sessions.forEach(session => {
          delete userDoc.session[session];
        });
      }
    }
    if (op === Cleanup.all) {
      delete userDoc.session;
    }
    return userDoc;
  }

  async removeUser(login: string, destroyDBs) {
    const promises = [];
    const userDoc = await this.getUser(login);
    const user = await this.logoutUserSessions(userDoc, Cleanup.all);
    if (destroyDBs !== true || !user.personalDBs) {
      return Promise.resolve();
    }
    Object.keys(user.personalDBs).forEach(userdb => {
      if (user.personalDBs[userdb].type === 'private') {
        promises.push(this.dbAuth.removeDB(userdb));
      }
    });
    await Promise.all(promises);
    return this.userDB.destroy(user._id, user._rev);
  }

  /**
   * Confirms the user:password that has been passed as Bearer Token
   * Todo: maybe just look in superlogin-users or try to access DB?
   */
  async confirmSession(key: string, password: string) {
    try {
      const doc = await this.dbAuth.retrieveKey(key);
      if (doc.expires > Date.now()) {
        const token: any = doc;
        token._id = token.user_id;
        token.key = key;
        delete token.user_id;
        delete token.name;
        delete token.type;
        delete token._rev;
        delete token.password_scheme;
        return this.session.confirmToken(token, password);
      } else {
        this.dbAuth.removeKeys(key);
      }
    } catch {}
    throw Session.invalidMsg;
  }

  generateSession(user_uid: string, roles: string[]) {
    return this.dbAuth.getApiKey().then(key => {
      const now = Date.now();
      return Promise.resolve({
        _id: user_uid,
        key: key.key,
        password: key.password,
        issued: now,
        expires: now + this.config.security.sessionLife * 1000,
        roles: roles
      });
    });
  }

  /** todo: why this method?? Also existed in Colin's version. */
  addUserDB(
    login: string, // todo: either pass uid or use find here
    dbName: string,
    type: string,
    designDocs?,
    permissions?: string[]
  ) {
    let userDoc: SlUserDoc;
    const dbConfig = this.dbAuth.getDBConfig(dbName, type || 'private');
    dbConfig.designDocs = designDocs || dbConfig.designDocs || '';
    dbConfig.permissions = permissions || dbConfig.permissions;
    return this.getUser(login)
      .then(result => {
        if (!result) {
          return Promise.reject({ status: 404, error: 'User not found' });
        }
        userDoc = result;
        return this.dbAuth.addUserDB(
          userDoc,
          dbName,
          dbConfig.designDocs,
          dbConfig.type,
          dbConfig.permissions,
          dbConfig.adminRoles,
          dbConfig.memberRoles
        );
      })
      .then(finalDBName => {
        if (!userDoc.personalDBs) {
          userDoc.personalDBs = {};
        }
        delete dbConfig.designDocs;
        // If permissions is specified explicitly it will be saved, otherwise will be taken from defaults every session
        if (!permissions) {
          delete dbConfig.permissions;
        }
        delete dbConfig.adminRoles;
        delete dbConfig.memberRoles;
        userDoc.personalDBs[finalDBName] = dbConfig;
        this.emitter.emit('user-db-added', userDoc.key, dbName);
        return this.userDB.insert(userDoc);
      });
  }

  addUserDBs(newUser: SlUserDoc) {
    // Add personal DBs
    if (!this.config.userDBs?.defaultDBs) {
      return Promise.resolve(newUser);
    }
    const promises = [];
    newUser.personalDBs = {};

    const processUserDBs = (dbList, type) => {
      dbList.forEach(userDBName => {
        const dbConfig = this.dbAuth.getDBConfig(userDBName);
        promises.push(
          this.dbAuth
            .addUserDB(
              newUser,
              userDBName,
              dbConfig.designDocs,
              type,
              dbConfig.permissions,
              dbConfig.adminRoles,
              dbConfig.memberRoles
            )
            .then(finalDBName => {
              delete dbConfig.permissions;
              delete dbConfig.adminRoles;
              delete dbConfig.memberRoles;
              delete dbConfig.designDocs;
              dbConfig.type = type;
              newUser.personalDBs[finalDBName] = dbConfig;
            })
        );
      });
    };

    // Just in case defaultDBs is not specified
    let defaultPrivateDBs = this.config.userDBs.defaultDBs.private;
    if (!Array.isArray(defaultPrivateDBs)) {
      defaultPrivateDBs = [];
    }
    processUserDBs(defaultPrivateDBs, 'private');
    let defaultSharedDBs = this.config.userDBs.defaultDBs.shared;
    if (!Array.isArray(defaultSharedDBs)) {
      defaultSharedDBs = [];
    }
    processUserDBs(defaultSharedDBs, 'shared');

    return Promise.all(promises).then(() => {
      return Promise.resolve(newUser);
    });
  }

  /** Cleans up all expired keys from the authentification-DB (`_users`) and superlogin's db. Call this regularily! */
  removeExpiredKeys() {
    return this.dbAuth.removeExpiredKeys();
  }
}
