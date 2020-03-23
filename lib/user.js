'use strict';

var url = require('url');
var Model = require('sofa-model');
var extend = require('extend');
var Session = require('./session');
var util = require('./util');
var DBAuth = require('./dbauth');

// regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L27
var EMAIL_REGEXP = /^(?=.{1,254}$)(?=.{1,64}@)[-!#$%&'*+/0-9=?A-Z^_`a-z{|}~]+(\.[-!#$%&'*+/0-9=?A-Z^_`a-z{|}~]+)*@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
var USER_REGEXP = /^[a-z0-9_-]{3,16}$/;

class User {
  #dbAuth;
  #session;
  #onCreateActions;
  #onLinkActions;
  constructor(config, userDB, couchAuthDB, mailer, emitter) {
    this.userDB = userDB;
    this.config = config;
    this.mailer = mailer;
    this.emitter = emitter;

    this.#dbAuth = new DBAuth(config, userDB, couchAuthDB);
    this.#session = new Session(config);
    this.#onCreateActions = [];
    this.#onLinkActions = [];

    // Token valid for 24 hours by default
    // Forget password token life
    this.tokenLife = config.getItem('security.tokenLife') || 86400;
    // Session token life
    this.sessionLife = config.getItem('security.sessionLife') || 86400;

    const emailUsername = config.getItem('local.emailUsername');
    this.passwordConstraints = {
      presence: true,
      length: {
        minimum: 6,
        message: 'must be at least 6 characters'
      },
      matches: 'confirmPassword'
    };
    this.passwordConstraints = extend(
      true,
      {},
      this.passwordConstraints,
      config.getItem('local.passwordConstraints')
    );

    // the validation functions are public
    this.validateUsername = function (username) {
      if (!username) {
        return Promise.resolve();
      }
      if (username.startsWith('_') || !username.match(USER_REGEXP)) {
        return Promise.resolve('Invalid username');
      }
      return userDB.query('auth/username', { key: username }).then(result => {
        if (result.rows.length === 0) {
          // Pass!
          return Promise.resolve();
        } else {
          return Promise.resolve('already in use');
        }
      });
    };

    this.validateEmail = function (email) {
      if (!email) {
        return Promise.resolve();
      }
      if (!email.match(EMAIL_REGEXP)) {
        return Promise.resolve('invalid email');
      }
      return userDB.query('auth/email', { key: email }).then(result => {
        if (result.rows.length === 0) {
          // Pass!
          return Promise.resolve();
        } else {
          return Promise.resolve('already in use');
        }
      });
    };

    this.validateEmailUsername = function (email) {
      if (!email) {
        return Promise.resolve();
      }
      if (!email.match(EMAIL_REGEXP)) {
        return Promise.resolve('invalid email');
      }
      return userDB.query('auth/emailUsername', { key: email }).then(
        result => {
          if (result.rows.length === 0) {
            return Promise.resolve();
          } else {
            return Promise.resolve('already in use');
          }
        },
        err => {
          throw new Error(err);
        }
      );
    };

    let userModel = {
      async: true,
      whitelist: ['name', 'username', 'email', 'password', 'confirmPassword'],
      customValidators: {
        validateEmail: this.validateEmail,
        validateUsername: this.validateUsername,
        validateEmailUsername: this.validateEmailUsername,
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
        roles: config.getItem('security.defaultRoles'),
        providers: ['local']
      },
      rename: {
        username: '_id'
      }
    };

    if (emailUsername) {
      delete userModel.validate.username;
      delete userModel.validate.email.validateEmail;
      delete userModel.rename.username;
      userModel.validate.email.validateEmailUsername = true;
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

    this.emailUsername = emailUsername;
  }

  /**
   * Use this to add as many functions as you want to transform the new user document before it is saved.
   * Your function should accept two arguments (userDoc, provider) and return a Promise that resolves to the modified user document.
   * onCreate functions will be chained in the order they were added.
   * @param {Function} fn
   */
  onCreate(fn) {
    if (typeof fn === 'function') {
      this.#onCreateActions.push(fn);
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
      this.#onLinkActions.push(fn);
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
    var promise;
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

  getUser(login) {
    var query;
    if (this.emailUsername) {
      query = 'emailUsername';
    } else {
      query = EMAIL_REGEXP.test(login) ? 'email' : 'username';
    }
    return this.userDB
      .query('auth/' + query, { key: login, include_docs: true })
      .then(results => {
        if (results.rows.length > 0) {
          return Promise.resolve(results.rows[0].doc);
        } else {
          return Promise.resolve(null);
        }
      });
  }

  createUser(form, req) {
    req = req || {};
    var finalUserModel = this.userModel;
    var newUserModel = this.config.getItem('userModel');
    if (typeof newUserModel === 'object') {
      var whitelist;
      if (newUserModel.whitelist) {
        whitelist = util.arrayUnion(
          this.userModel.whitelist,
          newUserModel.whitelist
        );
      }
      finalUserModel = extend(
        true,
        {},
        this.userModel,
        this.config.getItem('userModel')
      );
      finalUserModel.whitelist = whitelist || finalUserModel.whitelist;
    }
    var UserModel = Model(finalUserModel);
    var user = new UserModel(form);
    var newUser;
    return user
      .process()
      .then(result => {
        newUser = result;
        if (this.emailUsername) {
          newUser._id = newUser.email;
        }
        if (this.config.getItem('local.sendConfirmEmail')) {
          newUser.unverifiedEmail = {
            email: newUser.email,
            token: util.URLSafeUUID()
          };
          delete newUser.email;
        }
        return util.hashPassword(newUser.password);
      })
      .catch(err => {
        console.log('validation failed.');
        return Promise.reject({
          error: 'Validation failed',
          validationErrors: err,
          status: 400
        });
      })
      .then(hash => {
        // Store password hash
        newUser.local = {};
        newUser.local.salt = hash.salt;
        newUser.local.derived_key = hash.derived_key;
        delete newUser.password;
        delete newUser.confirmPassword;
        newUser.signUp = {
          provider: 'local',
          timestamp: new Date().toISOString(),
          ip: req.ip
        };
        return this.addUserDBs(newUser);
      })
      .then(newUser => {
        return this.logActivity(newUser._id, 'signup', 'local', req, newUser);
      })
      .then(newUser => {
        return this.processTransformations(
          this.#onCreateActions,
          newUser,
          'local'
        );
      })
      .then(finalNewUser => {
        return this.userDB.put(finalNewUser);
      })
      .then(result => {
        newUser._rev = result.rev;
        if (!this.config.getItem('local.sendConfirmEmail')) {
          return Promise.resolve();
        }
        return this.mailer.sendEmail(
          'confirmEmail',
          newUser.unverifiedEmail.email,
          { req: req, user: newUser }
        );
      })
      .then(() => {
        this.emitter.emit('signup', newUser, 'local');
        return Promise.resolve(newUser);
      });
  }

  /**
   * Creates a new user following authentication from an OAuth provider. If the user already exists it will update the profile.
   * @param {string} provider the name of the provider in lowercase, (e.g. 'facebook')
   * @param {string} auth credentials supplied by the provider
   * @param {any} profile the profile supplied by the provider
   * @param {any} req used just to log the user's ip if supplied
   */
  socialAuth(provider, auth, profile, req) {
    var user;
    var newAccount = false;
    var action;
    var baseUsername;
    req = req || {};
    var ip = req.ip;
    // It is important that we return a Bluebird promise so oauth.js can call .nodeify()
    return Promise.resolve()
      .then(() => {
        return this.userDB.query('auth/' + provider, {
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
            roles: this.config.getItem('security.defaultRoles'),
            signUp: {
              provider: provider,
              timestamp: new Date().toISOString(),
              ip: ip
            }
          };
          user[provider] = {};

          var emailFail = () => {
            return Promise.reject({
              error: 'Email already in use',
              message:
                'Your email is already in use. Try signing in first and then linking this account.',
              status: 409
            });
          };
          // Now we need to generate a username
          if (this.emailUsername) {
            if (!user.email) {
              return Promise.reject({
                error: 'No email provided',
                message:
                  'An email is required for registration, but ' +
                  provider +
                  " didn't supply one.",
                status: 400
              });
            }
            return this.validateEmailUsername(user.email).then(err => {
              if (err) {
                return emailFail();
              }
              return Promise.resolve(user.email.toLowerCase());
            });
          } else {
            if (profile.username) {
              baseUsername = profile.username.toLowerCase();
            } else {
              // If a username isn't specified we'll take it from the email
              if (user.email) {
                var parseEmail = user.email.split('@');
                baseUsername = parseEmail[0].toLowerCase();
              } else if (profile.displayName) {
                baseUsername = profile.displayName
                  .replace(/\s/g, '')
                  .toLowerCase();
              } else {
                baseUsername = profile.id.toLowerCase();
              }
            }
            return this.validateEmail(user.email).then(err => {
              if (err) {
                return emailFail();
              }
              return this.generateUsername(baseUsername);
            });
          }
        }
      })
      .then(finalUsername => {
        if (finalUsername) {
          user._id = finalUsername;
        }
        user[provider].auth = auth;
        user[provider].profile = profile;
        if (!user.name) {
          user.name = profile.displayName;
        }
        delete user[provider].profile._raw;
        if (newAccount) {
          return this.addUserDBs(user);
        } else {
          return Promise.resolve(user);
        }
      })
      .then(userDoc => {
        action = newAccount ? 'signup' : 'login';
        return this.logActivity(userDoc._id, action, provider, req, userDoc);
      })
      .then(userDoc => {
        if (newAccount) {
          return this.processTransformations(
            this.#onCreateActions,
            userDoc,
            provider
          );
        } else {
          return this.processTransformations(
            this.#onLinkActions,
            userDoc,
            provider
          );
        }
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        if (action === 'signup') {
          this.emitter.emit('signup', user, provider);
        }
        return Promise.resolve(user);
      });
  }

  linkSocial(user_id, provider, auth, profile, req) {
    req = req || {};
    var user;
    // Load user doc
    return Promise.resolve()
      .then(() => {
        return this.userDB.query('auth/' + provider, { key: profile.id });
      })
      .then(results => {
        if (results.rows.length === 0) {
          return Promise.resolve();
        } else {
          if (results.rows[0].id !== user_id) {
            return Promise.reject({
              error: 'Conflict',
              message:
                'This ' +
                provider +
                ' profile is already in use by another account.',
              status: 409
            });
          }
        }
      })
      .then(() => {
        return this.userDB.get(user_id);
      })
      .then(theUser => {
        user = theUser;
        // Check for conflicting provider
        if (user[provider] && user[provider].profile.id !== profile.id) {
          return Promise.reject({
            error: 'Conflict',
            message:
              'Your account is already linked with another ' +
              provider +
              'profile.',
            status: 409
          });
        }
        // Check email for conflict
        if (!profile.emails) {
          return Promise.resolve({ rows: [] });
        }
        if (this.emailUsername) {
          return this.userDB.query('auth/emailUsername', {
            key: profile.emails[0].value
          });
        } else {
          return this.userDB.query('auth/email', {
            key: profile.emails[0].value
          });
        }
      })
      .then(results => {
        var passed;
        if (results.rows.length === 0) {
          passed = true;
        } else {
          passed = true;
          results.rows.forEach(row => {
            if (row.id !== user_id) {
              passed = false;
            }
          });
        }
        if (!passed) {
          return Promise.reject({
            error: 'Conflict',
            message:
              'The email ' +
              profile.emails[0].value +
              ' is already in use by another account.',
            status: 409
          });
        } else {
          return Promise.resolve();
        }
      })
      .then(() => {
        // Insert provider info
        user[provider] = {};
        user[provider].auth = auth;
        user[provider].profile = profile;
        if (!user.providers) {
          user.providers = [];
        }
        if (user.providers.indexOf(provider) === -1) {
          user.providers.push(provider);
        }
        if (!user.name) {
          user.name = profile.displayName;
        }
        delete user[provider].profile._raw;
        return this.logActivity(user._id, 'link', provider, req, user);
      })
      .then(userDoc => {
        return this.processTransformations(
          this.#onLinkActions,
          userDoc,
          provider
        );
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        return Promise.resolve(user);
      });
  }

  /**
   * Removes the specified provider from the user's account. Local cannot be removed. If there is only one provider left it will fail.
   * Returns the modified user, if successful.
   * @param {string} user_id
   * @param {string} provider
   */
  unlink(user_id, provider) {
    var user;
    return this.userDB
      .get(user_id)
      .then(theUser => {
        user = theUser;
        if (!provider) {
          return Promise.reject({
            error: 'Unlink failed',
            message: 'You must specify a provider to unlink.',
            status: 400
          });
        }
        // We can only unlink if there are at least two providers
        if (
          !user.providers ||
          !(user.providers instanceof Array) ||
          user.providers.length < 2
        ) {
          return Promise.reject({
            error: 'Unlink failed',
            message: "You can't unlink your only provider!",
            status: 400
          });
        }
        // We cannot unlink local
        if (provider === 'local') {
          return Promise.reject({
            error: 'Unlink failed',
            message: "You can't unlink local.",
            status: 400
          });
        }
        // Check that the provider exists
        if (!user[provider] || typeof user[provider] !== 'object') {
          return Promise.reject({
            error: 'Unlink failed',
            message:
              'Provider: ' +
              util.capitalizeFirstLetter(provider) +
              ' not found.',
            status: 404
          });
        }
        delete user[provider];
        // Remove the unlinked provider from the list of providers
        user.providers.splice(user.providers.indexOf(provider), 1);
        return this.userDB.put(user);
      })
      .then(() => {
        return Promise.resolve(user);
      });
  }

  /**
   * Creates a new session for a user. provider is the name of the provider. (eg. 'local', 'facebook', twitter.)
   * req is used to log the IP if provided.
   * @param {string} user_id
   * @param {string} provider
   * @param {any} req
   *
   * @returns {import('../types/user').SlSession} the newly created session
   */
  createSession(user_id, provider, req) {
    var user;
    var newToken;
    var newSession;
    var password;
    req = req || {};
    var ip = req.ip;
    return this.userDB
      .get(user_id)
      .then(record => {
        user = record;
        return this.generateSession(user._id, user.roles);
      })
      .then(token => {
        password = token.password;
        newToken = token;
        newToken.provider = provider;
        return this.#session.storeToken(newToken);
      })
      .then(() => {
        return this.#dbAuth.storeKey(
          user_id,
          newToken.key,
          password,
          newToken.expires,
          user.roles
        );
      })
      .then(() => {
        // authorize the new session across all dbs
        if (!user.personalDBs) {
          return Promise.resolve();
        }
        return this.#dbAuth.authorizeUserSessions(
          user_id,
          user.personalDBs,
          newToken.key,
          user.roles
        );
      })
      .then(() => {
        if (!user.session) {
          user.session = {};
        }
        newSession = {
          issued: newToken.issued,
          expires: newToken.expires,
          provider: provider,
          ip: ip
        };
        user.session[newToken.key] = newSession;
        // Clear any failed login attempts
        if (provider === 'local') {
          if (!user.local) user.local = {};
          user.local.failedLoginAttempts = 0;
          delete user.local.lockedUntil;
        }
        return this.logActivity(user._id, 'login', provider, req, user);
      })
      .then(userDoc => {
        // Clean out expired sessions on login
        return this.logoutUserSessions(userDoc, 'expired');
      })
      .then(finalUser => {
        user = finalUser;
        return this.userDB.put(finalUser);
      })
      .then(() => {
        newSession.token = newToken.key;
        newSession.password = password;
        newSession.user_id = user._id;
        newSession.roles = user.roles;
        // Inject the list of userDBs
        if (typeof user.personalDBs === 'object') {
          var userDBs = {};
          var publicURL;
          if (this.config.getItem('dbServer.publicURL')) {
            var dbObj = url.parse(this.config.getItem('dbServer.publicURL'));
            dbObj.auth = newSession.token + ':' + newSession.password;
            publicURL = url.format(dbObj);
          } else {
            publicURL =
              this.config.getItem('dbServer.protocol') +
              newSession.token +
              ':' +
              newSession.password +
              '@' +
              this.config.getItem('dbServer.host') +
              '/';
          }
          Object.keys(user.personalDBs).forEach(finalDBName => {
            userDBs[user.personalDBs[finalDBName].name] =
              publicURL + finalDBName;
          });
          newSession.userDBs = userDBs;
        }
        if (user.profile) {
          newSession.profile = user.profile;
        }
        // New config option: also send name and user-ID
        if (this.config.getItem('local.sendNameAndUUID')) {
          if (user.name) {
            newSession.name = user.name;
          }
          if (user.user_uid) {
            newSession.user_uid = user.user_uid;
          }
        }
        this.emitter.emit('login', newSession, provider);
        return Promise.resolve(newSession);
      });
  }

  handleFailedLogin(user, req) {
    req = req || {};
    var maxFailedLogins = this.config.getItem('security.maxFailedLogins');
    if (!maxFailedLogins) {
      return Promise.resolve();
    }
    if (!user.local) {
      user.local = {};
    }
    if (!user.local.failedLoginAttempts) {
      user.local.failedLoginAttempts = 0;
    }
    user.local.failedLoginAttempts++;
    if (user.local.failedLoginAttempts > maxFailedLogins) {
      user.local.failedLoginAttempts = 0;
      user.local.lockedUntil =
        Date.now() + this.config.getItem('security.lockoutTime') * 1000;
    }
    return this.logActivity(user._id, 'failed login', 'local', req, user)
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        return Promise.resolve(!!user.local.lockedUntil);
      });
  }

  logActivity(user_id, action, provider, req, userDoc, saveDoc) {
    var logSize = this.config.getItem('security.userActivityLogSize');
    if (!logSize) {
      return Promise.resolve(userDoc);
    }
    var promise;
    if (userDoc) {
      promise = Promise.resolve(userDoc);
    } else {
      if (saveDoc !== false) {
        saveDoc = true;
      }
      promise = this.userDB.get(user_id);
    }
    return promise.then(theUser => {
      userDoc = theUser;
      if (!userDoc.activity || !(userDoc.activity instanceof Array)) {
        userDoc.activity = [];
      }
      var entry = {
        timestamp: new Date().toISOString(),
        action: action,
        provider: provider,
        ip: req.ip
      };
      userDoc.activity.unshift(entry);
      while (userDoc.activity.length > logSize) {
        userDoc.activity.pop();
      }
      if (saveDoc) {
        return this.userDB.put(userDoc).then(() => {
          return Promise.resolve(userDoc);
        });
      } else {
        return Promise.resolve(userDoc);
      }
    });
  }

  /**
   * Extends the life of your current token and returns updated token information.
   * The only field that will change is expires. Expired sessions are removed.
   * @param {string} key
   * @returns {import('../types/user').SlSession} the updated session
   */
  refreshSession(key) {
    var newSession;
    return this.#session
      .fetchToken(key)
      .then(oldToken => {
        newSession = oldToken;
        newSession.expires = Date.now() + this.sessionLife * 1000;
        return Promise.all([
          this.userDB.get(newSession._id),
          this.#session.storeToken(newSession)
        ]);
      })
      .then(results => {
        var userDoc = results[0];
        userDoc.session[key].expires = newSession.expires;
        // Clean out expired sessions on refresh
        return this.logoutUserSessions(userDoc, 'expired');
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        delete newSession.password;
        newSession.token = newSession.key;
        delete newSession.key;
        newSession.user_id = newSession._id;
        delete newSession._id;
        delete newSession.salt;
        delete newSession.derived_key;
        this.emitter.emit('refresh', newSession);
        return Promise.resolve(newSession);
      });
  }

  /**
   * Required form fields: token, password, and confirmPassword
   * @param {any} form
   * @param {any} req
   */
  resetPassword(form, req) {
    req = req || {};
    var ResetPasswordModel = Model(this.resetPasswordModel);
    var passwordResetForm = new ResetPasswordModel(form);
    var user;
    return passwordResetForm
      .validate()
      .then(
        () => {
          var tokenHash = util.hashToken(form.token);
          return this.userDB.query('auth/passwordReset', {
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
        return util.hashPassword(form.password);
      })
      .then(hash => {
        if (!user.local) {
          user.local = {};
        }
        user.local.salt = hash.salt;
        user.local.derived_key = hash.derived_key;
        if (user.providers.indexOf('local') === -1) {
          user.providers.push('local');
        }
        // logout user completely
        return this.logoutUserSessions(user, 'all');
      })
      .then(userDoc => {
        user = userDoc;
        delete user.forgotPassword;
        return this.logActivity(user._id, 'reset password', 'local', req, user);
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        this.emitter.emit('password-reset', user);
        return Promise.resolve(user);
      });
  }

  changePasswordSecure(user_id, form, req) {
    req = req || {};
    var ChangePasswordModel = Model(this.changePasswordModel);
    var changePasswordForm = new ChangePasswordModel(form);
    var user;
    return changePasswordForm
      .validate()
      .then(
        () => {
          return this.userDB.get(user_id);
        },
        err => {
          return Promise.reject({
            error: 'Validation failed',
            validationErrors: err,
            status: 400
          });
        }
      )
      .then(() => {
        return this.userDB.get(user_id);
      })
      .then(userDoc => {
        user = userDoc;
        if (user.local && user.local.salt && user.local.derived_key) {
          // Password is required
          if (!form.currentPassword) {
            return Promise.reject({
              error: 'Password change failed',
              message:
                'You must supply your current password in order to change it.',
              status: 400
            });
          }
          return util.verifyPassword(user.local, form.currentPassword);
        } else {
          return Promise.resolve();
        }
      })
      .then(
        () => {
          return this.changePassword(user._id, form.newPassword, user, req);
        },
        err => {
          return Promise.reject(
            err || {
              error: 'Password change failed',
              message: 'The current password you supplied is incorrect.',
              status: 400
            }
          );
        }
      )
      .then(() => {
        if (req.user && req.user.key) {
          return this.logoutOthers(req.user.key);
        } else {
          return Promise.resolve();
        }
      });
  }

  changePassword(user_id, newPassword, userDoc, req) {
    req = req || {};
    var promise, user;
    if (userDoc) {
      promise = Promise.resolve(userDoc);
    } else {
      promise = this.userDB.get(user_id);
    }
    return promise
      .then(
        doc => {
          user = doc;
          return util.hashPassword(newPassword);
        },
        err => {
          return Promise.reject({
            error: 'User not found',
            status: 404
          });
        }
      )
      .then(hash => {
        if (!user.local) {
          user.local = {};
        }
        user.local.salt = hash.salt;
        user.local.derived_key = hash.derived_key;
        if (user.providers.indexOf('local') === -1) {
          user.providers.push('local');
        }
        return this.logActivity(
          user._id,
          'changed password',
          'local',
          req,
          user
        );
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        this.emitter.emit('password-change', user);
      });
  }

  forgotPassword(email, req) {
    req = req || {};
    var user, token, tokenHash;
    return this.userDB
      .query('auth/email', { key: email, include_docs: true })
      .then(result => {
        if (!result.rows.length) {
          return Promise.reject({
            error: 'User not found',
            status: 404
          });
        }
        user = result.rows[0].doc;
        token = util.URLSafeUUID();
        if (this.config.getItem('local.tokenLengthOnReset')) {
          token = token.substring(
            0,
            this.config.getItem('local.tokenLengthOnReset')
          );
        }
        tokenHash = util.hashToken(token);
        user.forgotPassword = {
          token: tokenHash, // Store secure hashed token
          issued: Date.now(),
          expires: Date.now() + this.tokenLife * 1000
        };
        return this.logActivity(
          user._id,
          'forgot password',
          'local',
          req,
          user
        );
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      })
      .then(() => {
        return this.mailer.sendEmail(
          'forgotPassword',
          user.email || user.unverifiedEmail.email,
          { user: user, req: req, token: token }
        ); // Send user the unhashed token
      })
      .then(() => {
        this.emitter.emit('forgot-password', user);
        return Promise.resolve(user.forgotPassword);
      });
  }

  verifyEmail(token, req) {
    req = req || {};
    var user;
    return this.userDB
      .query('auth/verifyEmail', { key: token, include_docs: true })
      .then(result => {
        if (!result.rows.length) {
          return Promise.reject({ error: 'Invalid token', status: 400 });
        }
        user = result.rows[0].doc;
        user.email = user.unverifiedEmail.email;
        delete user.unverifiedEmail;
        this.emitter.emit('email-verified', user);
        return this.logActivity(user._id, 'verified email', 'local', req, user);
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      });
  }

  changeEmail(user_id, newEmail, req) {
    req = req || {};
    if (!req.user) {
      req.user = { provider: 'local' };
    }
    var user;
    return this.validateEmail(newEmail)
      .then(err => {
        if (err) {
          return Promise.reject(err);
        }
        return this.userDB.get(user_id);
      })
      .then(userDoc => {
        user = userDoc;
        if (this.config.getItem('local.sendConfirmEmail')) {
          user.unverifiedEmail = {
            email: newEmail,
            token: util.URLSafeUUID()
          };
          return this.mailer.sendEmail(
            'confirmEmail',
            user.unverifiedEmail.email,
            { req: req, user: user }
          );
        } else {
          user.email = newEmail;
          return Promise.resolve();
        }
      })
      .then(() => {
        this.emitter.emit('email-changed', user);
        return this.logActivity(
          user._id,
          'changed email',
          req.user.provider,
          req,
          user
        );
      })
      .then(finalUser => {
        return this.userDB.put(finalUser);
      });
  }

  addUserDB(user_id, dbName, type, designDocs, permissions) {
    var userDoc;
    var dbConfig = this.#dbAuth.getDBConfig(dbName, type || 'private');
    dbConfig.designDocs = designDocs || dbConfig.designDocs || '';
    dbConfig.permissions = permissions || dbConfig.permissions;
    return this.userDB
      .get(user_id)
      .then(result => {
        userDoc = result;
        return this.#dbAuth.addUserDB(
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
        this.emitter.emit('user-db-added', user_id, dbName);
        return this.userDB.put(userDoc);
      });
  }

  removeUserDB(user_id, dbName, deletePrivate, deleteShared) {
    var user;
    var update = false;
    return this.userDB
      .get(user_id)
      .then(userDoc => {
        user = userDoc;
        if (user.personalDBs && typeof user.personalDBs === 'object') {
          Object.keys(user.personalDBs).forEach(db => {
            if (user.personalDBs[db].name === dbName) {
              var type = user.personalDBs[db].type;
              delete user.personalDBs[db];
              update = true;
              if (type === 'private' && deletePrivate) {
                return this.#dbAuth.removeDB(dbName);
              }
              if (type === 'shared' && deleteShared) {
                return this.#dbAuth.removeDB(dbName);
              }
            }
          });
        }
        return Promise.resolve();
      })
      .then(() => {
        if (update) {
          this.emitter.emit('user-db-removed', user_id, dbName);
          return this.userDB.put(user);
        }
        return Promise.resolve();
      });
  }

  logoutUser(user_id, session_id) {
    var promise, user;
    if (user_id) {
      promise = this.userDB.get(user_id);
    } else {
      if (!session_id) {
        return Promise.reject({
          error: 'unauthorized',
          message: 'Either user_id or session_id must be specified',
          status: 401
        });
      }
      promise = this.userDB
        .query('auth/session', { key: session_id, include_docs: true })
        .then(results => {
          if (!results.rows.length) {
            return Promise.reject({
              error: 'unauthorized',
              status: 401
            });
          }
          return Promise.resolve(results.rows[0].doc);
        });
    }
    return promise
      .then(record => {
        user = record;
        user_id = record._id;
        return this.logoutUserSessions(user, 'all');
      })
      .then(() => {
        this.emitter.emit('logout', user_id);
        this.emitter.emit('logout-all', user_id);
        return this.userDB.put(user);
      });
  }

  logoutSession(session_id) {
    var user;
    var startSessions = 0;
    var endSessions = 0;
    return this.userDB
      .query('auth/session', { key: session_id, include_docs: true })
      .then(results => {
        if (!results.rows.length) {
          return Promise.reject({
            error: 'unauthorized',
            status: 401
          });
        }
        user = results.rows[0].doc;
        if (user.session) {
          startSessions = Object.keys(user.session).length;
          if (user.session[session_id]) {
            delete user.session[session_id];
          }
        }
        var promises = [];
        promises.push(this.#session.deleteTokens(session_id));
        promises.push(this.#dbAuth.removeKeys(session_id));
        if (user) {
          promises.push(this.#dbAuth.deauthorizeUser(user, session_id));
        }
        return Promise.all(promises);
      })
      .then(() => {
        // Clean out expired sessions
        return this.logoutUserSessions(user, 'expired');
      })
      .then(finalUser => {
        user = finalUser;
        if (user.session) {
          endSessions = Object.keys(user.session).length;
        }
        this.emitter.emit('logout', user._id);
        if (startSessions !== endSessions) {
          return this.userDB.put(user);
        } else {
          return Promise.resolve(false);
        }
      });
  }

  logoutOthers(session_id) {
    var user;
    return this.userDB
      .query('auth/session', { key: session_id, include_docs: true })
      .then(results => {
        if (results.rows.length) {
          user = results.rows[0].doc;
          if (user.session && user.session[session_id]) {
            return this.logoutUserSessions(user, 'other', session_id);
          }
        }
        return Promise.resolve();
      })
      .then(finalUser => {
        if (finalUser) {
          return this.userDB.put(finalUser);
        } else {
          return Promise.resolve(false);
        }
      });
  }

  logoutUserSessions(userDoc, op, currentSession) {
    // When op is 'other' it will logout all sessions except for the specified 'currentSession'
    var promises = [];
    var sessions;
    if (op === 'all' || op === 'other') {
      sessions = util.getSessions(userDoc);
    } else if (op === 'expired') {
      sessions = util.getExpiredSessions(userDoc, Date.now());
    }
    if (op === 'other' && currentSession) {
      // Remove the current session from the list of sessions we are going to delete
      var index = sessions.indexOf(currentSession);
      if (index > -1) {
        sessions.splice(index, 1);
      }
    }
    if (sessions.length) {
      // Delete the sessions from our session store
      promises.push(this.#session.deleteTokens(sessions));
      // Remove the keys from our couchDB auth database
      promises.push(this.#dbAuth.removeKeys(sessions));
      // Deauthorize keys from each personal database
      promises.push(this.#dbAuth.deauthorizeUser(userDoc, sessions));
      if (op === 'expired' || op === 'other') {
        sessions.forEach(session => {
          delete userDoc.session[session];
        });
      }
    }
    if (op === 'all') {
      delete userDoc.session;
    }
    return Promise.all(promises).then(() => {
      return Promise.resolve(userDoc);
    });
  }

  remove(user_id, destroyDBs) {
    var user;
    var promises = [];
    return this.userDB
      .get(user_id)
      .then(userDoc => {
        return this.logoutUserSessions(userDoc, 'all');
      })
      .then(userDoc => {
        user = userDoc;
        if (destroyDBs !== true || !user.personalDBs) {
          return Promise.resolve();
        }
        Object.keys(user.personalDBs).forEach(userdb => {
          if (user.personalDBs[userdb].type === 'private') {
            promises.push(this.#dbAuth.removeDB(userdb));
          }
        });
        return Promise.all(promises);
      })
      .then(() => {
        return this.userDB.remove(user);
      });
  }

  confirmSession(key, password) {
    return this.#session.confirmToken(key, password);
  }

  quitRedis() {
    return this.#session.quit();
  }

  generateSession(username, roles) {
    var getKey;
    if (this.config.getItem('dbServer.cloudant')) {
      getKey = require('./dbauth/cloudant').getAPIKey(this.userDB);
    } else {
      var token = util.URLSafeUUID();
      // Make sure our token doesn't start with illegal characters
      while (token[0] === '_' || token[0] === '-') {
        token = util.URLSafeUUID();
      }
      getKey = Promise.resolve({
        key: token,
        password: util.URLSafeUUID()
      });
    }
    return getKey.then(key => {
      var now = Date.now();
      return Promise.resolve({
        _id: username,
        key: key.key,
        password: key.password,
        issued: now,
        expires: now + this.sessionLife * 1000,
        roles: roles
      });
    });
  }

  /**
   * Adds numbers to a base name until it finds a unique database key
   * @param {string} base
   */
  generateUsername(base) {
    base = base.toLowerCase();
    var entries = [];
    var finalName;
    return this.userDB
      .allDocs({ startkey: base, endkey: base + '\uffff', include_docs: false })
      .then(results => {
        if (results.rows.length === 0) {
          return Promise.resolve(base);
        }
        for (var i = 0; i < results.rows.length; i++) {
          entries.push(results.rows[i].id);
        }
        if (entries.indexOf(base) === -1) {
          return Promise.resolve(base);
        }
        var num = 0;
        while (!finalName) {
          num++;
          if (entries.indexOf(base + num) === -1) {
            finalName = base + num;
          }
        }
        return Promise.resolve(finalName);
      });
  }

  addUserDBs(newUser) {
    // Add personal DBs
    if (!this.config.getItem('userDBs.defaultDBs')) {
      return Promise.resolve(newUser);
    }
    var promises = [];
    newUser.personalDBs = {};

    var processUserDBs = (dbList, type) => {
      dbList.forEach(userDBName => {
        var dbConfig = this.#dbAuth.getDBConfig(userDBName);
        promises.push(
          this.#dbAuth
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
    var defaultPrivateDBs = this.config.getItem('userDBs.defaultDBs.private');
    if (!Array.isArray(defaultPrivateDBs)) {
      defaultPrivateDBs = [];
    }
    processUserDBs(defaultPrivateDBs, 'private');
    var defaultSharedDBs = this.config.getItem('userDBs.defaultDBs.shared');
    if (!Array.isArray(defaultSharedDBs)) {
      defaultSharedDBs = [];
    }
    processUserDBs(defaultSharedDBs, 'shared');

    return Promise.all(promises).then(() => {
      return Promise.resolve(newUser);
    });
  }

  removeExpiredKeys() {
    this.#dbAuth.removeExpiredKeys.bind(this.#dbAuth);
  }
}

module.exports = User;
