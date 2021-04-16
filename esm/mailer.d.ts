import { Config } from './types/config';
export declare class Mailer {
    private config;
    private transporter;
    constructor(config: Partial<Config>);
    sendEmail(templateName: string, email: any, locals: any): Promise<any>;
}
