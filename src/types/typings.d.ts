import {
  Document,
  DocumentScope as NanoDocumentScope,
  ServerScope as NanoServerScope,
  IdentifiedDocument,
  MaybeRevisionedDocument
} from 'nano';
import {
  DocumentScope as CloudantDocumentScope,
  ServerScope as CloudantServerScope
} from '@cloudant/cloudant';
import { Request } from 'express';

export type ServerScope = NanoServerScope | CloudantServerScope;
export type DocumentScope<D> = NanoDocumentScope<D> | CloudantDocumentScope<D>;

export interface IdentifiedObj {
  name: string;
  type: string;
}

export interface CouchDbAuthDoc
  extends IdentifiedDocument,
    MaybeRevisionedDocument,
    IdentifiedObj {
  user_id: string;
  password?: string;
  expires: number;
  roles: string[];
  provider: string;
  password_scheme?: string;
  iterations?: number;
  derived_key?: string;
  salt?: string;
}

export interface HashResult {
  salt?: string;
  derived_key?: string;
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
  local: LocalHashObj;
  activity?: UserActivity[];
  forgotPassword?: PasswortResetEntry;
  unverifiedEmail?: { email: string; token: string };
  signUp: SignUpObj;
  personalDBs: PersonalDBCollection;
  email: string;
  session: SessionCollection;
  profile: any;
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

export interface SlUser {
  provider?: string;
  _id?: string;
  key?: string;
  roles?: string[];
  user_id?: string;
}

export interface SlRequest extends Request {
  user: SlUser;
}
