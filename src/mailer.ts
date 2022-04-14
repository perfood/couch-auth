import nodemailer from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';
import { join } from 'path';
import {
  parseCompositeTemplate,
  parseTemplatesDirectly
} from './template-utils';
import { Config } from './types/config';

export class Mailer {
  private config: Partial<Config>;
  private transporter: Mail;
  constructor(config: Partial<Config>) {
    this.config = config;
    if (config.testMode?.noEmail) {
      this.transporter = nodemailer.createTransport(
        require('nodemailer-stub-transport')()
      );
    } else {
      this.transporter = nodemailer.createTransport(
        config.mailer.transport ?? config.mailer.options
      );
    }
  }

  /**
   * Use the same nodemailer config that couch-auth uses to send out an email.
   * Internally, `req` (the sent request), `user` (the sl-user doc) and `data`
   * defined in the config are always available.
   *
   * @param templateId the entry under the `emails` property in the config
   * @param recepient the recepient's email address
   * @param data additional data can be passed to `nunjucks.render()`
   */
  sendEmail(templateId: string, recepient: string, data?: Record<string, any>) {
    // load the template and parse it
    const templateConfig = this.config.emailTemplates[templateId];
    if (!templateConfig) {
      return Promise.reject('No template entry for "' + templateId + '".');
    }
    const templateDirectory =
      this.config.emailTemplateFolder ?? join(__dirname, './templates/email');
    let templates: { html: string; text: string };
    const templateData = { ...templateConfig, ...data };

    try {
      templates = parseCompositeTemplate(
        templateDirectory,
        templateId,
        templateData
      );
    } catch (error) {
      templates = parseTemplatesDirectly(
        templateDirectory,
        templateId,
        templateData
      );
      if (!templates.html && !templates.text) {
        return Promise.reject(`No template file found for "${templateId}"`);
      }
    }

    // form the email
    let mailOptions: Mail.Options = {
      from: this.config.mailer.fromEmail,
      to: recepient,
      subject: templateConfig.subject,
      ...templates
    };
    if (this.config.mailer.messageConfig) {
      mailOptions = { ...this.config.mailer.messageConfig, ...mailOptions };
    }
    if (this.config.testMode?.debugEmail) {
      console.log(mailOptions);
    }
    // send the message
    return this.transporter.sendMail(mailOptions);
  }
}
