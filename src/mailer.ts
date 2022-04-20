import nodemailer from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';
import { join } from 'path';
import {
  parseCompositeTemplate,
  parseTemplatesDirectly
} from './template-utils';
import { Config, EmailTemplate } from './types/config';
import { timeoutPromise } from './util';

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
   * @param data additional data directly passed to `nunjucks.render()`. Don't
   * add anything called `data` in here!
   */
  public async sendEmail(
    templateId: string,
    recepient: string,
    data?: Record<string, any>
  ): Promise<any> {
    // load the template and parse it
    const templateConfig: EmailTemplate =
      this.config.emailTemplates.templates[templateId];
    if (!templateConfig) {
      return Promise.reject('No template entry for "' + templateId + '".');
    }
    const templateDirectory =
      this.config.emailTemplates.folder ?? join(__dirname, './templates/email');
    let templates: { html: string; text: string };
    const templateData = {
      subject: templateConfig.subject,
      data: { ...this.config.emailTemplates.data, ...templateConfig.data },
      ...data
    };

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
    if (this.config.mailer.retryOnError) {
      return this.sendMailWithBackoff(mailOptions, 0);
    } else {
      return this.transporter.sendMail(mailOptions);
    }
  }

  private async sendMailWithBackoff(
    mailOptions: Mail.Options,
    attempt: number
  ) {
    try {
      return this.transporter.sendMail(mailOptions);
    } catch (error) {
      attempt += 1;
      if (attempt > this.config.mailer.retryOnError.maxRetries) {
        throw error;
      }
      await timeoutPromise(
        1000 *
          this.config.mailer.retryOnError.initialBackoffSeconds *
          2 ** attempt
      );
      return this.sendMailWithBackoff(mailOptions, attempt);
    }
  }
}
