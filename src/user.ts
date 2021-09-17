'use strict';
import Model, { Sofa } from '@sl-nx/sofa-model';
import merge from 'deepmerge';
import { EventEmitter } from 'events';
import { Request } from 'express';
import { DocumentScope } from 'nano';
import url from 'url';
import { v4 as uuidv4 } from 'uuid';
import { DBAuth } from './dbauth';
import { Hashing } from './hashing';
import { Mailer } from './mailer';
import { Session } from './session';
import { Config } from './types/config';
import {
  ConsentRequest,
  CouchDbAuthDoc,
  HashResult,
  LocalHashObj,
  RegistrationForm,
  SessionObj,
  SlAction,
  SlLoginSession,
  SlRefreshSession,
  SlRequest,
  SlUserDoc,
  SlUserNew
} from './types/typings';
import { DbManager } from './user/DbManager';
import {
  arrayUnion,
  EMAIL_REGEXP,
  extractCurrentConsents,
  getExpiredSessions,
  getSessions,
  hashToken,
  hyphenizeUUID,
  removeHyphens,
  URLSafeUUID,
  USER_REGEXP,
  verifyConsentUpdate
} from './util';

enum Cleanup {
  'expired' = 'expired',
  'other' = 'other',
  'all' = 'all'
}
export enum ValidErr {
  'exists' = 'already in use',
  'emailInvalid' = 'invalid email',
  'userInvalid' = 'invalid username'
}

export class User {
  private dbAuth: DBAuth;
  private userDbManager: DbManager;
  private session: Session;
  private onCreateActions: SlAction[];
  private onLinkActions: SlAction[];
  private hasher: Hashing;

  passwordConstraints;
  /**
   * Checks that a username is valid and not in use.
   * Resolves with nothing if successful.
   * Resolves with an error object in failed.
   */
  public validateUsername: (v: string) => Promise<string | void>;
  /**
   * Checks that an email is valid and not in use.
   * Resolves with nothing if successful.
   * Resolves with an error object in failed.
   */
  public validateEmail: (v: string) => Promise<string | void>;
  /** Validates whether the _format_ matches the config */
  private validateConsents: (
    v: Record<string, ConsentRequest>
  ) => string | void;

  userModel: Sofa.AsyncOptions;
  resetPasswordModel: Sofa.AsyncOptions;
  changePasswordModel: Sofa.AsyncOptions;

  constructor(
    protected config: Config,
    protected userDB: DocumentScope<SlUserDoc>,
    couchAuthDB: DocumentScope<CouchDbAuthDoc>,
    protected mailer: Mailer,
    public emitter: EventEmitter
  ) {
    this.dbAuth = new DBAuth(config, userDB, couchAuthDB);
    this.onCreateActions = [];
    this.onLinkActions = [];
    this.hasher = new Hashing(config);
    this.session = new Session(this.hasher);
    this.userDbManager = new DbManager(userDB, config);
    this.passwordConstraints = config.local.passwordConstraints;

    // the validation functions are public and callable without `this` context
    this.validateUsername = async function (username: string) {
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

    this.validateEmail = async function (
      email: string
    ): Promise<string | void> {
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

    const requiredConsents: string[] = [];
    for (const [k, v] of Object.entries(config.local.consents ?? {})) {
      if (v.required) {
        requiredConsents.push(k);
      }
    }
    this.validateConsents = function (
      initialConsents: Record<string, ConsentRequest>
    ): string | void {
      if (initialConsents === undefined && !requiredConsents.length) {
        return;
      }
      const err = verifyConsentUpdate(initialConsents, config);
      if (err) {
        return err;
      }
      const providedConsents = new Set(Object.keys(initialConsents));
      if (requiredConsents.some(c => !providedConsents.has(c))) {
        return 'must include all required consents';
      }
    };

    const userModel: Sofa.AsyncOptions = {
      async: true,
      whitelist: ['name', 'username', 'email', 'password', 'confirmPassword'],
      customValidators: {
        validateEmail: this.validateEmail,
        validateUsername: this.validateUsername,
        matches: this.matches,
        validateConsents: this.validateConsents
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

    if (config.local.emailUsername) {
      delete userModel.validate.username;
    }
    if (config.local.consents) {
      userModel.whitelist.push('consents');
      userModel.validate.consents = {
        validateConsents: true
      };
      if (requiredConsents.length) {
        userModel.validate.consents.presence = true;
      }
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

  /**
   * Hashes a password using PBKDF2 and returns an object containing `salt` and
   * `derived_key`.
   */
  public hashPassword(pw: string): Promise<HashResult> {
    return this.hasher.hashUserPassword(pw);
  }

  /**
   * Verifies a password using a hash object. If you have a user doc, pass in
   * `local` as the hash object.
   * @returns resolves with `true` if valid, `false` if not
   */
  public verifyPassword(obj: LocalHashObj, pw: string): Promise<boolean> {
    return this.hasher.verifyUserPassword(obj, pw);
  }

  /**
   * Use this to add as many functions as you want to transform the new user
   * document before it is saved. Your function should accept two arguments
   * (userDoc, provider) and return a Promise that resolves to the modified
   * user document.
   * onCreate functions will be chained in the order they were added.
   * @param {Function} fn
   */
  public onCreate(fn: SlAction) {
    if (typeof fn === 'function') {
      this.onCreateActions.push(fn);
    } else {
      throw new TypeError('onCreate: You must pass in a function');
    }
  }

  /**
   * Does the same thing as onCreate, but is called every time a user links a
   * new provider, or their profile information is refreshed.
   * This allows you to process profile information and, for example, create a
   * master profile.
   * If an object called profile exists inside the user doc it will be passed
   * to the client along with session information at each login.
   */
  public onLink(fn: SlAction) {
    if (typeof fn === 'function') {
      this.onLinkActions.push(fn);
    } else {
      throw new TypeError('onLink: You must pass in a function');
    }
  }

  /** Validation function for ensuring that two fields match */
  private matches(value, option, key, attributes) {
    if (attributes && attributes[option] !== value) {
      return 'does not match ' + option;
    }
  }

  private async processTransformations(
    fnArray: SlAction[],
    userDoc: SlUserDoc,
    provider: string
  ): Promise<SlUserDoc> {
    for (const fn of fnArray) {
      userDoc = await fn.call(null, userDoc, provider);
    }
    return userDoc;
  }

  /**
   * retrieves by email (default) or username or uuid if the config options are
   * set. Rejects if no valid format.
   */
  public getUser(login: string, allowUUID = false): Promise<SlUserDoc | null> {
    return this.userDbManager.getUser(login, allowUUID);
  }

  private async handleEmailExists(email: string): Promise<void> {
    const existingUser = await this.userDbManager.getUserBy('email', email);
    await this.mailer.sendEmail('signupExistingEmail', email, {
      user: existingUser
    });
    this.emitter.emit('signup-attempt', existingUser, 'local');
  }

  /**
   * Creates a new local user with a username/email and password.
   * @param form requires the following: `username` and/or `email`, `password`,
   * and `confirmPassword`. `name` is optional. Any additional fields must be
   * whitelisted in your config under `userModel` or they will be removed.
   * @param req additional request data passed to the email template
   * @returns
   */
  public async createUser(
    form: RegistrationForm,
    req?
  ): Promise<void | SlUserDoc> {
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
    let newUser: Partial<SlUserNew> = {};
    let hasError = false;
    try {
      newUser = await user.process();
    } catch (err) {
      hasError = true;
      let doThrow = true;
      if (
        err.email &&
        this.config.local.emailUsername &&
        this.config.local.requireEmailConfirm
      ) {
        const inUseIdx = err.email.findIndex((s: string) =>
          s.endsWith(ValidErr.exists)
        );
        if (inUseIdx >= 0) {
          err.email.splice(inUseIdx, 1);
          if (err.email.length === 0) {
            delete err.email;
            if (Object.keys(err).length === 0) {
              this.handleEmailExists(form.email);
              doThrow = false;
            }
          }
        }
      }
      if (doThrow) {
        throw {
          error: 'Validation failed',
          validationErrors: err,
          status: 400
        };
      }
    }

    return new Promise(async (resolve, reject) => {
      newUser = await this.prepareNewUser(newUser);
      if (hasError || !this.config.security.loginOnRegistration) {
        resolve(hasError ? undefined : (newUser as SlUserDoc));
      }
      if (!hasError) {
        const finalUser = await this.insertNewUserDocument(newUser, req);
        this.emitter.emit('signup', finalUser, 'local');
        if (this.config.security.loginOnRegistration) {
          resolve(finalUser);
        }
      }
    });
  }

  private async prepareNewUser(newUser: Partial<SlUserNew>) {
    const uid = uuidv4();
    // todo: remove, this is just for backwards compat...
    if (this.config.local.sendNameAndUUID) {
      newUser.user_uid = uid;
    }
    newUser._id = removeHyphens(uid);
    if (this.config.local.emailUsername) {
      newUser.key = await this.userDbManager.generateUsername();
    }
    if (this.config.local.sendConfirmEmail) {
      newUser.unverifiedEmail = {
        email: newUser.email,
        token: URLSafeUUID()
      };
      delete newUser.email;
    }
    newUser.local = await this.hashPassword(newUser.password ?? URLSafeUUID());
    delete newUser.password;
    delete newUser.confirmPassword;
    if (newUser.consents) {
      for (const [k, v] of Object.entries(newUser.consents)) {
        (v as any).timestamp = new Date().toISOString();
        newUser.consents[k] = [v as any];
      }
    }
    newUser.signUp = {
      provider: 'local',
      timestamp: new Date().toISOString()
    };
    return newUser;
  }

  private async insertNewUserDocument(newUser: Partial<SlUserNew>, req?) {
    newUser = await this.addUserDBs(newUser as SlUserDoc);
    newUser = this.userDbManager.logActivity(
      'signup',
      'local',
      newUser as SlUserDoc
    );
    const finalNewUser = await this.processTransformations(
      this.onCreateActions,
      newUser as SlUserDoc,
      'local'
    );
    const result = await this.userDB.insert(finalNewUser);
    newUser._rev = result.rev;
    if (this.config.local.sendConfirmEmail) {
      await this.mailer.sendEmail(
        'confirmEmail',
        newUser.unverifiedEmail.email,
        {
          req: req,
          user: newUser
        }
      );
    }
    return newUser as SlUserDoc;
  }

  /**
   * Creates a new user following authentication from an OAuth provider.
   * If the user already exists it will update the profile.
   * @param provider the name of the provider in lowercase, (e.g. 'facebook')
   * @param {any} auth credentials supplied by the provider
   * @param {any} profile the profile supplied by the provider
   */
  public async createUserSocial(
    provider: string,
    auth,
    profile
  ): Promise<SlUserDoc> {
    let user: Partial<SlUserDoc>;
    let newAccount = false;
    // This used to be consumed by `.nodeify` from Bluebird. I hope `callbackify` works just as well...
    const results = await this.userDB.view('auth', provider, {
      key: profile.id,
      include_docs: true
    });

    if (results.rows.length > 0) {
      user = results.rows[0].doc;
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
      // Now we need to generate a username
      if (!user.email) {
        throw {
          error: 'No email provided',
          message: `An email is required for registration, but ${provider} didn't supply one.`,
          status: 400
        };
      }
      const emailCheck = await this.validateEmail(user.email);
      if (emailCheck) {
        throw {
          error: 'Email already in use',
          message:
            'Your email is already in use. Try signing in first and then linking this account.',
          status: 409
        };
      }
      user.key = await this.userDbManager.generateUsername();
    }

    user[provider].auth = auth;
    user[provider].profile = profile;
    if (!user.name) {
      user.name = profile.displayName;
    }
    delete user[provider].profile._raw;
    if (newAccount) {
      user._id = removeHyphens(uuidv4());
      user = await this.addUserDBs(user as SlUserDoc);
    }
    let finalUser = await this.processTransformations(
      newAccount ? this.onCreateActions : this.onLinkActions,
      user as SlUserDoc,
      provider
    );
    const action = newAccount ? 'signup' : 'create-social';
    finalUser = this.userDbManager.logActivity(action, provider, finalUser);
    await this.userDB.insert(finalUser);
    this.emitter.emit(action, user, provider);
    return user as SlUserDoc;
  }

  /**
   * like `createUserSocial`, but for an already existing user identified by
   * `login`
   */
  public async linkUserSocial(
    login: string,
    provider: string,
    auth,
    profile
  ): Promise<SlUserDoc> {
    let userDoc = await this.userDbManager.initLinkSocial(
      login,
      provider,
      auth,
      profile
    );
    userDoc = await this.processTransformations(
      this.onLinkActions,
      userDoc,
      provider
    );
    userDoc = this.userDbManager.logActivity('link-social', provider, userDoc);
    await this.userDB.insert(userDoc);
    this.emitter.emit('link-social', userDoc, provider);
    return userDoc;
  }

  /**
   * Removes the specified provider from the user's account.
   * `local` cannot be removed. If there is only one provider left it will fail.
   * Returns the modified user, if successful.
   * @param login email, username or UUID
   * @param provider the OAuth provider
   */
  public unlinkUserSocial(login: string, provider: string): Promise<SlUserDoc> {
    return this.userDbManager.unlink(login, provider);
  }

  /**
   * Creates a new session for a user
   * @param login the email, username or UUID (depending on your config)
   * @param provider 'local' or one of the configured OAuth providers
   * @param byUUID if `true`, interpret `login` always as UUID
   * @returns the new session
   */
  public async createSession(
    login: string,
    provider: string,
    byUUID = false
  ): Promise<SlLoginSession> {
    let user = byUUID
      ? await this.userDbManager.getUserByUUID(login)
      : await this.getUser(login);
    if (!user) {
      console.warn('createSession - could not retrieve: ', login);
      throw { error: 'Bad Request', status: 400 };
    }
    const user_uid = user._id;
    const token = this.generateSession(user_uid, user.roles, provider);
    const password = token.password;
    token.provider = provider;
    await this.dbAuth.storeKey(
      user.key,
      hyphenizeUUID(user_uid),
      token.key,
      password,
      token.expires,
      user.roles,
      provider
    );
    // authorize the new session across all dbs
    if (user.personalDBs) {
      await this.dbAuth.authorizeUserSessions(user.personalDBs, token.key);
    }
    if (!user.session) {
      user.session = {};
    }
    const newSession: Partial<SlLoginSession> = {
      issued: token.issued,
      expires: token.expires,
      provider: provider
    };
    user.session[token.key] = newSession as SessionObj;
    // Clear any failed login attempts
    if (provider === 'local') {
      if (!user.local) user.local = {};
      delete user.local.failedLoginAttempts;
      delete user.local.lockedUntil;
    }
    const userDoc = this.userDbManager.logActivity('login', provider, user);
    // Clean out expired sessions on login
    const finalUser = await this.logoutUserSessions(userDoc, Cleanup.expired);
    user = finalUser;
    await this.userDB.insert(finalUser);
    newSession.token = token.key;
    newSession.password = password;
    newSession.user_id = user.key;
    newSession.roles = user.roles;
    // Inject the list of userDBs
    if (typeof user.personalDBs === 'object') {
      const userDBs = {};
      let publicURL: string;
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

  /**
   * Extends the life of your current token and returns updated token information.
   * The only field that will change is expires. Expired sessions are removed.
   * todo:
   * - handle error if invalid state occurs that doc is not present.
   */
  public async refreshSession(key: string): Promise<SlRefreshSession> {
    let userDoc = await this.userDbManager.findUserDocBySession(key);
    const newExpiration = Date.now() + this.config.security.sessionLife * 1000;
    userDoc.session[key].expires = newExpiration;
    // Clean out expired sessions on refresh
    userDoc = await this.logoutUserSessions(userDoc, Cleanup.expired);
    userDoc = this.userDbManager.logActivity('refresh', key, userDoc);
    await this.userDB.insert(userDoc);
    await this.dbAuth.extendKey(key, newExpiration);

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
  public async resetPassword(
    form,
    req: Partial<Request> = undefined
  ): Promise<SlUserDoc> {
    req = req || {};
    const ResetPasswordModel = Model(this.resetPasswordModel);
    const passwordResetForm = new ResetPasswordModel(form);
    let user: SlUserDoc;
    try {
      await passwordResetForm.validate();
    } catch (err) {
      throw {
        error: 'Validation failed',
        validationErrors: err,
        status: 400
      };
    }
    const tokenHash = hashToken(form.token);
    const results = await this.userDB.view('auth', 'passwordReset', {
      key: tokenHash,
      include_docs: true
    });
    if (!results.rows.length) {
      throw { status: 400, error: 'Invalid token' };
    }
    user = results.rows[0].doc;
    if (user.forgotPassword.expires < Date.now()) {
      return Promise.reject({ status: 400, error: 'Token expired' });
    }
    const hash = await this.hashPassword(form.password);

    if (!user.local) {
      user.local = {};
    }
    user.local = { ...user.local, ...hash };
    if (user.providers.indexOf('local') === -1) {
      user.providers.push('local');
    }
    // logout user completely
    user = await this.logoutUserSessions(user, Cleanup.all);
    delete user.forgotPassword;
    if (user.unverifiedEmail) {
      user = await this.markEmailAsVerified(user);
    }
    user = this.userDbManager.logActivity('password-reset', 'local', user);
    await this.userDB.insert(user);
    await this.sendModifiedPasswordEmail(user, req);
    this.emitter.emit('password-reset', user);
    return user;
  }

  public async changePasswordSecure(login: string, form, req?): Promise<void> {
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
      await this.logoutOthers(req.user.key);
    }
  }

  public async forgotUsername(
    email: string,
    req: Partial<Request>
  ): Promise<void> {
    if (!email || !email.match(EMAIL_REGEXP)) {
      throw { error: 'invalid email', status: 400 };
    }
    req = req || {};
    try {
      const user = await this.userDbManager.getUserBy('email', email);
      if (!user) {
        throw {
          error: 'User not found',
          status: 404
        };
      }
      await this.mailer.sendEmail(
        'forgotUsername',
        user.email || user.unverifiedEmail.email,
        { user: user, req: req }
      );
      this.emitter.emit('forgot-username', user);
    } catch (err) {
      this.emitter.emit('forgot-username-attempt', email);
      if (err.status !== 404) {
        throw err;
      }
    }
  }

  /**
   * Changes the password of a user
   * @param user_uid the UUID of the user (without hypens, `_id` in `sl-users`)
   * @param newPassword the new password for the user
   * @param userDoc the `SlUserDoc` of the user. Will be retrieved by the
   * @param req additional data that will be passed to the template as `req`
   */
  public async changePassword(
    user_uid: string,
    newPassword: string,
    userDoc: SlUserDoc,
    req: any
  ): Promise<void> {
    req = req || {};
    if (!userDoc) {
      try {
        userDoc = await this.userDB.get(user_uid);
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
    const finalUser = this.userDbManager.logActivity(
      'password-change',
      'local',
      userDoc
    );
    await this.userDB.insert(finalUser);
    await this.sendModifiedPasswordEmail(userDoc, req);
    this.emitter.emit('password-change', userDoc);
  }

  private async sendModifiedPasswordEmail(user: SlUserDoc, req): Promise<void> {
    if (this.config.local.sendPasswordChangedEmail) {
      await this.mailer.sendEmail(
        'modifiedPassword',
        user.email || user.unverifiedEmail.email,
        { user: user, req: req }
      );
    }
  }

  /**
   * sends out a passwort reset email, if the user exists
   * @param email email of the user
   * @param req additional request data, passed to the template as `req`
   */
  public async forgotPassword(email: string, req: any): Promise<void> {
    if (!email || !email.match(EMAIL_REGEXP)) {
      return Promise.reject({ error: 'invalid email', status: 400 });
    }
    req = req || {};
    try {
      const user = await this.userDbManager.getUserBy('email', email);
      if (!user) {
        throw {
          error: 'User not found', // not sent as response.
          status: 404
        };
      }
      this.completeForgotPassRequest(user, req).catch(err => {
        this.emitter.emit('forgot-password-attempt', email);
        console.warn('forgot-password: failed for ', user._id, ' with: ', err);
      });
    } catch (err) {
      this.emitter.emit('forgot-password-attempt', email);
      if (err.status !== 404) {
        return Promise.reject(err);
      }
    }
  }

  private async completeForgotPassRequest(
    user: SlUserDoc,
    req: Partial<Request>
  ) {
    let token = URLSafeUUID();
    if (this.config.local.tokenLengthOnReset) {
      token = token.substring(0, this.config.local.tokenLengthOnReset);
    }
    const tokenHash = hashToken(token);
    user.forgotPassword = {
      token: tokenHash, // Store secure hashed token
      issued: Date.now(),
      expires: Date.now() + this.config.security.tokenLife * 1000
    };
    user = this.userDbManager.logActivity('forgot-password', 'local', user);
    await this.userDB.insert(user);
    await this.mailer.sendEmail(
      'forgotPassword',
      user.email || user.unverifiedEmail.email,
      { user: user, req: req, token: token }
    );
    this.emitter.emit('forgot-password', user);
  }

  /**
   * Marks the user's email as verified. `token` comes from the confirmation
   * email. Resolves if successful, rejects if token is invalid.
   * @param token
   */
  public verifyEmail(token: string) {
    let user: SlUserDoc;
    return this.userDB
      .view('auth', 'verifyEmail', { key: token, include_docs: true })
      .then(result => {
        if (!result.rows.length) {
          return Promise.reject({ error: 'Invalid token', status: 400 });
        }
        user = result.rows[0].doc;
        return this.markEmailAsVerified(user);
      })
      .then(finalUser => {
        return this.userDB.insert(finalUser);
      });
  }

  private async markEmailAsVerified(userDoc) {
    userDoc.email = userDoc.unverifiedEmail.email;
    delete userDoc.unverifiedEmail;
    this.emitter.emit('email-verified', userDoc);
    return this.userDbManager.logActivity('email-verified', 'local', userDoc);
  }

  private async completeEmailChange(
    login: string,
    newEmail: string,
    req: Partial<SlRequest>
  ) {
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
    const finalUser = this.userDbManager.logActivity(
      'email-changed',
      req.user.provider,
      user
    );
    await this.userDB.insert(finalUser);
    this.emitter.emit('email-changed', user);
  }

  /**
   * Changes the user's email. If email verification is enabled
   * (`local.sendConfirmEmail`), a confirmation email will be sent out.
   * @param login user's email, username or UUID (depending on your config)
   * @param newEmail the new email
   * @param req additional request data, passed to the template as `req`
   */
  public async changeEmail(
    login: string,
    newEmail: string,
    req: Partial<SlRequest>
  ) {
    req = req || {};
    if (!req.user) {
      req.user = { provider: 'local' };
    }
    newEmail = newEmail.toLowerCase().trim();
    const emailError = await this.validateEmail(newEmail);
    if (emailError) {
      this.emitter.emit('email-change-attempt', login, newEmail);
      if (
        this.config.local.requireEmailConfirm &&
        emailError === ValidErr.exists
      ) {
        return;
      } else {
        throw emailError;
      }
    }
    this.completeEmailChange(login, newEmail, req);
  }

  /**
   * Deauthorizes the specified database from the user's account, and optionally destroys it.
   * @param login email, username or UUID of the user (depending on your config)
   * @param dbName full path for a shared db, or base name for a private db
   * @param deletePrivate when true, will destroy a private DB with the `dbName`
   * @param deleteShared when true, will destroy a shared DB with the `dbName.
   *                     Caution: may destroy other users' data!
   */
  public async removeUserDB(
    login: string,
    dbName: string,
    deletePrivate: boolean = false,
    deleteShared: boolean = false
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
   * Logs out all of a user's sessions. One of `login` or `session_id` must be
   * provided.
   * @param login the email, username or UUID of the user
   * @param session_id the id of the session - i.e. `org.couchdb.user:${suffix}`
   * @returns
   */
  public async logoutAll(login: string, session_id: string) {
    let user: SlUserDoc;
    if (login) {
      user = await this.getUser(login);
    } else if (session_id) {
      user = await this.userDbManager.findUserDocBySession(session_id);
      login = session_id;
    }
    if (!user) {
      return Promise.reject({
        error: 'unauthorized',
        status: 401
      });
    }
    await this.logoutUserSessions(user, Cleanup.all);
    user = this.userDbManager.logActivity('logout-all', login, user);
    this.emitter.emit('logout-all', user.key);
    return this.userDB.insert(user);
  }

  /**
   * Logs out the specified session. Note that in case of a server error, it can
   * happen that only the entry in the `_users` DB is removed. This deauthorizes
   * the user, but the records in `sl-users` might not be accurate in that case.
   */
  public async logoutSession(session_id: string) {
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
        user = this.userDbManager.logActivity('logout', session_id, user);
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

  /** Logs out all of a user's sessions, except for the one specified. */
  public async logoutOthers(session_id: string) {
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

  private async logoutUserSessions(
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

  /**
   * Removes a user and terminates all of his sessions
   * @param login the user's uuid or email/key
   * @param destroyDBs use `true` to also remove the personal DBs of the user
   * @param reason additional information to be emmitted by `'user-deleted'`
   */
  public async removeUser(login: string, destroyDBs = false, reason?: string) {
    const promises = [];
    let user = await this.getUser(login, true);
    if (!user) {
      throw { status: 404, error: 'not found' };
    }
    user = await this.logoutUserSessions(user, Cleanup.all);
    if (destroyDBs && user.personalDBs) {
      Object.keys(user.personalDBs).forEach(userdb => {
        if (user.personalDBs[userdb].type === 'private') {
          promises.push(this.dbAuth.removeDB(userdb));
        }
      });
      await Promise.all(promises);
    }

    await this.userDB.destroy(user._id, user._rev);
    this.emitter.emit('user-deleted', user, reason);
  }

  /**
   * Confirms the user:password that has been passed as Bearer Token. Returns
   * the passed `key` + the `user_uid`, `expires`, `roles`, `provider` from the
   * the contents of the doc in the `_users`-DB.
   */
  public async confirmSession(key: string, password: string) {
    try {
      const doc = await this.dbAuth.retrieveKey(key);
      if (doc.expires > Date.now()) {
        doc._id = doc.user_id;
        delete doc.user_id;
        delete doc.name;
        delete doc.type;
        delete doc._rev;
        delete doc.password_scheme;
        return { key, ...(await this.session.confirmToken(doc, password)) } as {
          key: string;
          user_uid: string;
          expires: number;
          roles: string[];
          provider: string;
        };
      } else {
        this.dbAuth.removeKeys(key);
      }
    } catch {
      await this.session.confirmToken({}, password);
    }
    throw Session.invalidMsg;
  }

  private generateSession(user_uid: string, roles: string[], provider: string) {
    const key = this.dbAuth.getApiKey();
    const now = Date.now();
    return {
      ...key,
      _id: user_uid,
      issued: now,
      expires: now + this.config.security.sessionLife * 1000,
      roles,
      provider
    };
  }

  /**
   * Associates a new database with the user's account. Will also authenticate
   * all existing sessions with the new database. If the optional fields are not
   * specified, they will be taken from `userDBs.model.{dbName}` or
   * `userDBs.model._default` in your config.
   * @param login  the `key`, `email` or `_id` (user_uid) of the user
   * @param dbName the name of the database. For a shared db, this is the actual
   * path. For a private db userDBs.privatePrefix will be prepended, and
   * `${user_uid}` appended.
   * @param type 'private' (default) or 'shared'
   * @param designDocs the name of the designDoc (if any) that will be seeded.
   */
  public addUserDB(
    login: string,
    dbName: string,
    type: 'private' | 'shared' = 'private',
    designDocs?
  ) {
    let userDoc: SlUserDoc;
    const dbConfig = this.dbAuth.getDBConfig(dbName, type);
    dbConfig.designDocs = designDocs || dbConfig.designDocs || '';
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
          dbConfig.adminRoles,
          dbConfig.memberRoles
        );
      })
      .then(finalDBName => {
        if (!userDoc.personalDBs) {
          userDoc.personalDBs = {};
        }
        delete dbConfig.designDocs;
        delete dbConfig.adminRoles;
        delete dbConfig.memberRoles;
        userDoc.personalDBs[finalDBName] = dbConfig;
        this.emitter.emit('user-db-added', userDoc.key, dbName);
        return this.userDB.insert(userDoc);
      });
  }

  /**
   * Adds the private and authorises access to the shared userDBs
   */
  private addUserDBs(userDoc: SlUserDoc) {
    if (!this.config.userDBs?.defaultDBs) {
      return Promise.resolve(userDoc);
    }
    const promises = [];
    userDoc.personalDBs = {};

    const processUserDBs = (dbList, type) => {
      dbList.forEach(userDBName => {
        const dbConfig = this.dbAuth.getDBConfig(userDBName);
        promises.push(
          this.dbAuth
            .addUserDB(
              userDoc,
              userDBName,
              dbConfig.designDocs,
              type,
              dbConfig.adminRoles,
              dbConfig.memberRoles
            )
            .then(finalDBName => {
              delete dbConfig.adminRoles;
              delete dbConfig.memberRoles;
              delete dbConfig.designDocs;
              dbConfig.type = type;
              userDoc.personalDBs[finalDBName] = dbConfig;
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
      return Promise.resolve(userDoc);
    });
  }

  /**
   * Deauthorizes all expired keys from the authentification-DB (`_users`) and
   * superlogin's db (`sl-users`). Call this regularily!
   */
  public removeExpiredKeys() {
    return this.dbAuth.removeExpiredKeys();
  }

  /**
   * @internal
   * returns the latest entries of the current user's consents
   */
  async getCurrentConsents(login: string) {
    const userDoc: SlUserDoc = await this.userDbManager.getUser(login, true);
    return extractCurrentConsents(userDoc);
  }

  /**
   * @internal
   * validates and performs the update to the consents, returning the updated
   * consents if successful
   */
  async updateConsents(
    login: string,
    consentUpdate: Record<string, ConsentRequest>
  ) {
    const validationErrMsg = verifyConsentUpdate(consentUpdate, this.config);
    if (validationErrMsg) {
      throw { error: 'bad request', status: 400, message: validationErrMsg };
    }
    let userDoc: SlUserDoc = await this.userDbManager.getUser(login, true);
    // it's also possible that a _new_ consent has been introduced!
    for (const [consentKey, consentRequest] of Object.entries(consentUpdate)) {
      if (!userDoc.consents) {
        userDoc.consents = {};
      }
      if (!userDoc.consents[consentKey]) {
        userDoc.consents[consentKey] = [];
      }
      userDoc.consents[consentKey].push({
        ...consentRequest,
        timestamp: new Date().toISOString()
      });
    }
    userDoc = this.userDbManager.logActivity('consents', undefined, userDoc);
    await this.userDB.insert(userDoc);
    this.emitter.emit('consents', userDoc);
    return extractCurrentConsents(userDoc);
  }
}
