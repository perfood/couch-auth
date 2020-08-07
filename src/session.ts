'use strict';
import { Hashing } from './hashing';
import { LocalHashObj } from './types/typings';

export class Session {
  static invalidMsg = 'invalid token';
  constructor(private hasher: Hashing) {}

  /** Confirms the token and removes the information that should not be sent to the client */
  async confirmToken(token: LocalHashObj, password: string) {
    try {
      await this.hasher.verifyUserPassword(token, password);
      delete token.salt;
      delete token.derived_key;
      delete token.iterations;
      return token;
    } catch (error) {
      console.log('confirmToken - got err: ', error);
      throw Session.invalidMsg;
    }
  }
}
