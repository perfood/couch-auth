import { render } from 'ejs';
import { readFileSync } from 'fs';
import nodemailer from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';
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
   * Use the same nodemailer config that Superlogin uses to send out an email.
   * @param templateName the entry under the `emails` property in the config
   * @param recepient the recepient's email address
   * @param data additional data can be passed to `ejs.render()`
   */
  sendEmail(
    templateName: string,
    recepient: string,
    data?: Record<string, any>
  ) {
    // load the template and parse it
    let templateFiles = this.config.emails[templateName]?.templates;
    if (!templateFiles) {
      const templateFile = this.config.emails[templateName]?.template;
      if (!templateFile) {
        return Promise.reject('No templates found for "' + templateName + '".');
      }
      templateFiles = [templateFile];
    }

    const readTemplates = templateFiles.map(t => readFileSync(t, 'utf8'));
    for (let i = 0; i < templateFiles.length; i++) {
      if (!readTemplates[i]) {
        return Promise.reject(
          'Failed to locate template file: ' + templateFiles[i]
        );
      }
    }
    const renderedTemplates = readTemplates.map(t => render(t, data));

    // form the email
    const subject = this.config.emails[templateName].subject;
    let formats = this.config.emails[templateName].formats;
    if (!formats) {
      const format = this.config.emails[templateName].format;
      if (!format) {
        return Promise.reject('No formats specified for: ' + templateName);
      }
      formats = [format];
    }
    if (formats.length !== renderedTemplates.length) {
      return Promise.reject(
        'Different number of read templates and requested formats for template: ' +
          templateName
      );
    }
    let mailOptions: Mail.Options = {
      from: this.config.mailer.fromEmail,
      to: recepient,
      subject: subject
    };
    if (this.config.mailer.messageConfig) {
      mailOptions = { ...this.config.mailer.messageConfig, ...mailOptions };
    }

    for (let i = 0; i < formats.length; i++) {
      mailOptions[formats[i]] = renderedTemplates[i];
    }
    if (this.config.testMode?.debugEmail) {
      console.log(mailOptions);
    }
    // send the message
    return this.transporter.sendMail(mailOptions);
  }
}
