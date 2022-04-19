import { join } from 'path';
import { Config } from '../types/config';

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
    designDocDir: join(__dirname, '/designDocs'),
    userDB: 'sl_users',
    couchAuthDB: '_users'
  },
  emailTemplates: {
    folder: join(__dirname, './templates/email'),
    data: { year: new Date().getFullYear() },
    templates: {
      confirmEmail: {
        subject: 'Please confirm your email'
      },
      confirmEmailChange: {
        subject: 'Please confirm your new email'
      },
      forgotPassword: {
        subject: 'Your password reset link'
      },
      modifiedPassword: {
        subject: 'Your password has been modified'
      },
      signupExistingEmail: {
        subject: 'You already have registered with us'
      },
      forgotUsername: {
        subject: 'Your username request'
      }
    }
  }
};
