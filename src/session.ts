'use strict';
import { LocalHashObj } from './types/typings';
import { verifyPassword } from './util';

export class Session {
  static invalidMsg = 'invalid token';
  constructor(config?) {}

  /** Confirms the token and removes the information that should not be sent to the client */
  async confirmToken(token: LocalHashObj, password: string) {
    try {
      await verifyPassword(token, password);
      delete token.salt;
      delete token.derived_key;
      delete token.iterations;
      return token;
    } catch (error) {
      throw Session.invalidMsg;
    }
  }
}
