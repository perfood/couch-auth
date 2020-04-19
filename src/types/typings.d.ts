import { Document, IdentifiedDocument, MaybeRevisionedDocument } from 'nano';

export interface IdentifiedObj {
  name: string;
  type: string;
}

export interface CouchDbAuthDoc
  extends IdentifiedDocument,
    MaybeRevisionedDocument,
    IdentifiedObj {
  user_id: string;
  password: string;
  expires: number;
  roles: string[];
  provider: string;
}

export interface HashResult {
  salt: string;
  derived_key: string;
}

export interface LocalHashObj extends HashResult {
  failedLoginAttempts: number;
  iterations?: number;
}

export interface SignUpObj {
  provider: string;
  timestamp: string;
  ip: string;
}

export interface PersonalDBCollection {
  [dbName: string]: IdentifiedObj;
}

export interface SessionObj {
  issued: number;
  expires: number;
  provider: string;
  ip: string;
}

export interface SessionCollection {
  [session: string]: SessionObj;
}

export interface SlUserDoc extends Document, IdentifiedObj {
  user_uid: string;
  roles: string[];
  providers: string[];
  local: LocalHashObj;
  signUp: SignUpObj;
  personalDBs: PersonalDBCollection;
  email: string;
  session: SessionCollection;
}

export interface SlSession {
  expires: number;
  issued: number;
  password: string;
  provider: string;
  roles: string[];
  token: string;
  userDBs: { [db: string]: string };
  user_id: string;
  ip?: string;
  profile?: string;
  user_uid?: string;
  name?: string;
}
