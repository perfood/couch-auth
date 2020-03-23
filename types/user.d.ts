export interface SlSession {
  expires: string;
  issued: string;
  password: string;
  provider: string;
  roles: string[];
  token: string;
  userDBs: { [db: string]: string };
  user_id: string;
  ip?: number;
  profile?: string;
  user_uid?: string;
  name?: string;
}
