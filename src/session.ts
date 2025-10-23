'use strict';
import { verifyCouchPassword } from './hashing-session';
import { LocalHashObj } from './types/typings';

export class Session {
  static invalidErr = { status: 401, message: 'invalid token' };
  constructor() {}

  /**
   * Confirms that the password matches with the provided token and returns the
   * token, if successful, but removes the information that should not be sent
   * to the client.
   */
  async confirmToken<T extends LocalHashObj>(
    token: T,
    password: string
  ): Promise<Omit<T, 'salt' | 'derived_key' | 'iterations'>> {
    try {
      await verifyCouchPassword(token, password);
      delete token.salt;
      delete token.derived_key;
      delete token.iterations;
      return token;
    } catch (error) {
      throw Session.invalidErr;
    }
  }
}
