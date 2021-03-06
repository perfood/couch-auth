import {
  capitalizeFirstLetter,
  EMAIL_REGEXP,
  generateSlUserKey,
  hyphenizeUUID,
  removeHyphens,
  USER_REGEXP
} from '../util';
import { Config } from '../types/config';
import { DocumentScope } from '../types/typings';
import { validate as isUUID } from 'uuid';
import { SlUserDoc } from '../types/typings';

export class DbManager {
  constructor(
    private userDB: DocumentScope<SlUserDoc>,
    private config: Partial<Config>
  ) {}

  getUserByUUID(uuid: string): Promise<SlUserDoc> {
    return this.userDB.get(removeHyphens(uuid)).catch(err => {
      if (err.status === 404) {
        return null;
      } else {
        return Promise.reject(err);
      }
    });
  }

  /**
   * returns the `SlUserDoc`, if found, else `null`.
   * Todo: rejecting with 404 might be better!
   */
  getUserBy(
    identifier: '_id' | 'email' | 'key',
    login: string
  ): Promise<SlUserDoc> {
    if (identifier === '_id') {
      return this.getUserByUUID(login);
    }
    return this.userDB
      .view('auth', identifier, { key: login, include_docs: true })
      .then(results => {
        if (results.rows.length === 1) {
          return Promise.resolve(results.rows[0].doc);
        } else if (results.rows.length > 1) {
          console.error(
            `Invalid state - got multiple docs for ${identifier}: ${login}`
          );
          return Promise.reject({
            status: 500,
            error: 'Internal Server Error'
          });
        } else {
          return Promise.resolve(null);
        }
      });
  }

  async findUserDocBySession(key: string): Promise<SlUserDoc | undefined> {
    const results = await this.userDB.view('auth', 'session', {
      key,
      include_docs: true
    });
    if (results.rows.length > 0) {
      return results.rows[0].doc as SlUserDoc;
    } else {
      return undefined;
    }
  }

  /**
   * generates a unique user_id used as `key` for backwards compatibility with
   * old `user_id`s. Returns a URL-Safe UUID, shortened to length 8.
   */
  async generateUsername(): Promise<string> {
    let keyOK = false;
    let newKey: string;
    while (!keyOK) {
      newKey = generateSlUserKey();
      keyOK = await this.verifyNewDBKey(newKey);
    }
    return newKey;
  }

  async verifyNewDBKey(newKey: string): Promise<boolean> {
    const keyQuery = {
      selector: {
        key: newKey
      },
      fields: ['key']
    };
    const results = await this.userDB.find(keyQuery);
    return results.docs.length === 0;
  }

  getMatchingIdentifier(login: string): '_id' | 'email' | 'key' {
    if (
      this.config.local.uuidLogin &&
      [32, 36].includes(login.length) &&
      !login.includes('@')
    ) {
      const testStr = login.length === 32 ? hyphenizeUUID(login) : login;
      if (isUUID(testStr)) {
        return '_id';
      }
    } else if (this.config.local.usernameLogin && USER_REGEXP.test(login)) {
      return 'key';
    } else if (EMAIL_REGEXP.test(login)) {
      return 'email';
    }
    return undefined;
  }

  getUser(login: string): Promise<SlUserDoc | null> {
    const identifier = this.getMatchingIdentifier(login);
    if (!identifier) {
      console.log('no matching identifier for login: ', login);
      return Promise.reject({ error: 'Bad request', status: 400 });
    }
    return this.getUserBy(identifier, login);
  }

  async initLinkSocial(
    login: string,
    provider: string,
    auth,
    profile
  ): Promise<SlUserDoc> {
    let user: SlUserDoc;
    // Load user doc
    const results = await this.userDB.view('auth', provider, {
      key: profile.id,
      include_docs: true
    });
    if (results.rows.length === 0) {
      user = await this.getUser(login);
    } else {
      user = results.rows[0].doc;
      const match = this.getMatchingIdentifier(login);
      if (match === '_id') {
        login = removeHyphens(login);
      }
      if (user[match] !== login) {
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
    if (profile.emails) {
      const mailResults = await this.userDB.view('auth', 'email', {
        key: profile.emails[0].value,
        include_docs: true
      });
      if (mailResults.rows.length > 0) {
        const match = this.getMatchingIdentifier(login);
        if (match === '_id') {
          login = removeHyphens(login);
        }
        if (mailResults.rows.some(row => row.doc[match] !== login)) {
          throw {
            error: 'Conflict',
            message:
              'The email ' +
              profile.emails[0].value +
              ' is already in use by another account.',
            status: 409
          };
        }
      }
    }

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
    return user;
  }

  async unlink(user_id, provider): Promise<SlUserDoc> {
    const user = await this.getUser(user_id);
    if (!user) {
      return Promise.reject({
        error: 'Bad Request',
        message: 400
      });
    }
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
        message: 'Provider: ' + capitalizeFirstLetter(provider) + ' not found.',
        status: 404
      });
    }
    delete user[provider];
    // Remove the unlinked provider from the list of providers
    user.providers.splice(user.providers.indexOf(provider), 1);
    await this.userDB.insert(user);
    return user;
  }
}
