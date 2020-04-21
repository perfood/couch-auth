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
  failedLoginAttempts?: number;
  iterations?: number;
  lockedUntil?: number;
}

export interface SignUpObj {
  provider: string;
  timestamp: string;
  ip: string;
}

export interface PersonalDBCollection {
  [dbName: string]: IdentifiedObj;
}

export interface TimeRestricted {
  issued: number;
  expires: number;
}

export interface SessionObj extends TimeRestricted {
  provider: string;
  ip: string;
}

export interface SessionCollection {
  [session: string]: SessionObj;
}

export interface UserActivity {
  timestamp: string;
  action: string;
  provider: string;
  ip: string;
}

export interface PasswortResetEntry extends TimeRestricted {
  token: string;
}

export interface SlUserDoc extends Document, IdentifiedObj {
  user_uid: string;
  roles: string[];
  providers: string[];
  local: Partial<LocalHashObj>;
  activity?: UserActivity[];
  forgotPassword?: PasswortResetEntry;
  unverifiedEmail?: { email: string };
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
