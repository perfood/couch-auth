'use strict';
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const nodemailer_1 = __importDefault(require("nodemailer"));
const fs_1 = __importDefault(require("fs"));
const ejs_1 = __importDefault(require("ejs"));
class Mailer {
    constructor(config) {
        // Initialize the transport mechanism with nodermailer
        this.config = config;
        const customTransport = config.getItem('mailer.transport');
        if (config.getItem('testMode.noEmail')) {
            this.transporter = nodemailer_1.default.createTransport(require('nodemailer-stub-transport')());
        }
        else if (customTransport) {
            this.transporter = nodemailer_1.default.createTransport(customTransport(config.getItem('mailer.options')));
        }
        else {
            this.transporter = nodemailer_1.default.createTransport(config.getItem('mailer.options'));
        }
    }
    sendEmail(templateName, email, locals) {
        // load the template and parse it
        let templateFiles = this.config.getItem(`emails.${templateName}.templates`);
        if (!templateFiles) {
            const templateFile = this.config.getItem('emails.' + templateName + '.template');
            if (!templateFile) {
                return Promise.reject('No templates found for "' + templateName + '".');
            }
            templateFiles = [templateFile];
        }
        const readTemplates = templateFiles.map(t => fs_1.default.readFileSync(t, 'utf8'));
        for (let i = 0; i < templateFiles.length; i++) {
            if (!readTemplates[i]) {
                return Promise.reject('Failed to locate template file: ' + templateFiles[i]);
            }
        }
        const renderedTemplates = readTemplates.map(t => ejs_1.default.render(t, locals));
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
            return Promise.reject('Different number of read templates and requested formats for template: ' +
                templateName);
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
exports.Mailer = Mailer;
