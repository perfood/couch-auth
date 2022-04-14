import { join } from "path";

export const config = {
  port: 5000,
  emailTemplateFolder: join(__dirname, '../templates/email'),
  testMode: {
    noEmail: true,
    debugEmail: false,
    oauthDebug: true
  },
  dbServer: {
    protocol: (process.env.COUCH_PROTOCOL || 'http://') as
      | 'http://'
      | 'https://',
    host: process.env.COUCH_HOST || 'localhost:5984',
    user: process.env.COUCH_USER || 'admin',
    password: process.env.COUCH_PASS || 'password',
    userDB: 'sl_test-users',
    couchAuthDB: 'sl_test-keys'
  },
  security: {
    disabledRoutes: [],
    userActivityLogSize: 10
  },
  local: {
    sendConfirmEmail: true,
    sendPasswordChangedEmail: true,
    // todo: adjust these three once the old default behaviour works.
    usernameLogin: true,
    emailUsername: false,
    requireEmailConfirm: false,
    consents: {
      privacy: {
        minVersion: 2,
        currentVersion: 3,
        required: true
      },
      marketing: {
        minVersion: 2,
        currentVersion: 3,
        required: false
      }
    }
  },
  mailer: {
    fromEmail: 'me@example.com'
  },
  userDBs: {
    designDocDir: __dirname + '/ddocs',
    privatePrefix: 'test'
  },
  providers: {
    facebook: {
      clientID: 'FAKE_ID',
      clientSecret: 'FAKE_SECRET'
    },
    twitter: {
      consumerKey: 'FAKE_KEY',
      consumerSecret: 'FAKE_SECRET'
    }
  }
};
