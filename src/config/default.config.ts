import path from 'path';
import { Config } from '../types/config.model';

/**
 * These are the default settings that will be used if you don't override them
 * in your config
 */
export const defaultConfig: Config = {
  security: {
    defaultRoles: ['user'],
    sessionLife: 86400,
    tokenLife: 86400,
    loginOnRegistration: false,
    loginOnPasswordReset: false,
    disabledRoutes: [
      'validate-username',
      'validate-email',
      'unlink',
      'session',
      'forgot-username'
    ]
  },
  local: {
    passwordConstraints: {
      presence: true,
      length: {
        minimum: 8,
        message: 'must be at least 8 characters'
      },
      matches: 'confirmPassword'
    },
    usernameField: 'username',
    passwordField: 'password',
    emailUsername: true,
    emailLogin: true,
    usernameLogin: false,
    uuidLogin: false,
    requireEmailConfirm: true,
    sendConfirmEmail: true,
    requirePasswordOnEmailChange: true,
    sendPasswordChangedEmail: true
  },
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    designDocDir: path.join(__dirname, '/designDocs'),
    userDB: 'sl_users',
    couchAuthDB: '_users'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../../templates/email/confirm-email.ejs'),
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: path.join(
        __dirname,
        '../../templates/email/forgot-password.ejs'
      ),
      format: 'text'
    },
    modifiedPassword: {
      subject: 'Your password has been modified',
      template: path.join(
        __dirname,
        '../../templates/email/modified-password.ejs'
      ),
      format: 'text'
    },
    signupExistingEmail: {
      subject: 'You already have registered with us',
      template: path.join(
        __dirname,
        '../../templates/email/signup-email-exists.ejs'
      ),
      format: 'text'
    },
    forgotUsername: {
      subject: 'Your username request',
      template: path.join(
        __dirname,
        '../../templates/email/forgot-username.ejs'
      ),
      format: 'text'
    }
  }
};
