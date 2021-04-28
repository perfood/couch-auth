import { Config } from './types/config';
import Mail from 'nodemailer/lib/mailer';
import nodemailer from 'nodemailer';
import { readFileSync } from 'fs';
import { render } from 'ejs';

export class Mailer {
  private config: Partial<Config>;
  private transporter: Mail;
  constructor(config: Partial<Config>) {
    // Initialize the transport mechanism with nodermailer
    this.config = config;
    const customTransport = config.mailer.transport;
    if (config.testMode?.noEmail) {
      this.transporter = nodemailer.createTransport(
        require('nodemailer-stub-transport')()
      );
    } else if (customTransport) {
      this.transporter = nodemailer.createTransport(
        customTransport(config.mailer.options)
      );
    } else {
      this.transporter = nodemailer.createTransport(
        // @ts-ignore
        config.mailer.options
      );
    }
  }

  sendEmail(templateName: string, email, locals) {
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
    const renderedTemplates = readTemplates.map(t => render(t, locals));

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
      to: email,
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
