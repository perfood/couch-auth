'use strict';
const fs = require('fs');
const nodemailer = require('nodemailer');
const ejs = require('ejs');

export class Mailer {
  constructor(config) {
    // Initialize the transport mechanism with nodermailer
    this.config = config;
    const customTransport = config.getItem('mailer.transport');
    if (config.getItem('testMode.noEmail')) {
      this.transporter = nodemailer.createTransport(
        require('nodemailer-stub-transport')()
      );
    } else if (customTransport) {
      this.transporter = nodemailer.createTransport(
        customTransport(config.getItem('mailer.options'))
      );
    } else {
      this.transporter = nodemailer.createTransport(
        config.getItem('mailer.options')
      );
    }
  }

  sendEmail(templateName, email, locals) {
    // load the template and parse it
    let templateFiles = this.config.getItem(`emails.${templateName}.templates`);
    if (!templateFiles) {
      const templateFile = this.config.getItem(
        'emails.' + templateName + '.template'
      );
      if (!templateFile) {
        return Promise.reject('No templates found for "' + templateName + '".');
      }
      templateFiles = [templateFile];
    }

    const readTemplates = templateFiles.map(t => fs.readFileSync(t, 'utf8'));
    for (let i = 0; i < templateFiles.length; i++) {
      if (!readTemplates[i]) {
        return Promise.reject(
          'Failed to locate template file: ' + templateFiles[i]
        );
      }
    }
    const renderedTemplates = readTemplates.map(t => ejs.render(t, locals));

    // form the email
    const subject = this.config.getItem('emails.' + templateName + '.subject');
    let formats = this.config.getItem('emails.' + templateName + '.formats');
    if (!formats) {
      const format = this.config.getItem('emails.' + templateName + '.format');
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
    const mailOptions = {
      from: this.config.getItem('mailer.fromEmail'),
      to: email,
      subject: subject
    };

    for (let i = 0; i < formats.length; i++) {
      mailOptions[formats[i]] = renderedTemplates[i];
    }
    if (this.config.getItem('testMode.debugEmail')) {
      console.log(mailOptions);
    }
    // send the message
    return this.transporter.sendMail(mailOptions);
  }
}
