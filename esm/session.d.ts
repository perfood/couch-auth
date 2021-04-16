import { Hashing } from './hashing';
import { LocalHashObj } from './types/typings';
export declare class Session {
    private hasher;
    static invalidMsg: string;
    constructor(hasher: Hashing);
    /** Confirms the token and removes the information that should not be sent to the client */
    confirmToken(token: LocalHashObj, password: string): Promise<LocalHashObj>;
}
