'use strict';
export class Session {
    constructor(hasher) {
        this.hasher = hasher;
    }
    /** Confirms the token and removes the information that should not be sent to the client */
    async confirmToken(token, password) {
        try {
            await this.hasher.verifyUserPassword(token, password);
            delete token.salt;
            delete token.derived_key;
            delete token.iterations;
            return token;
        }
        catch (error) {
            throw Session.invalidMsg;
        }
    }
}
Session.invalidMsg = 'invalid token';
