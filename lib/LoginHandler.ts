import * as xmlrpc from 'xmlrpc';
import * as crypto from 'crypto';
import * as util from 'util';
import * as uuid from 'uuid';
import * as url from 'url';
import { LoginParameters } from './classes/LoginParameters';
import { LoginResponse } from './classes/LoginResponse';
import { ClientEvents } from './classes/ClientEvents';
import { BotOptionFlags } from './enums/BotOptionFlags';

declare module 'xmlrpc' {
    interface Client {
        methodCall(method: string, params: any[], callback: (error: Error, value: any) => void): void;
        methodCallAsync(method: string, params: any[]): Promise<any>;  
    } 
}

export class LoginHandler
{
    private clientEvents: ClientEvents;
    private options: BotOptionFlags;

    static GenerateMAC(): string
    {
        const hexDigits = '0123456789ABCDEF';
        let macAddress = '';
        for (let i = 0; i < 6; i++)
        {
            macAddress += hexDigits.charAt(Math.round(Math.random() * 15));
            macAddress += hexDigits.charAt(Math.round(Math.random() * 15));
            if (i !== 5)
            {
                macAddress += ':';
            }
        }

        return macAddress;
    }

    constructor(ce: ClientEvents, options: BotOptionFlags)
    {
        this.clientEvents = ce;
        this.options = options;
    }

    async Login(params: LoginParameters): Promise<LoginResponse>
    {
        const loginURI = url.parse(params.url);

        const secure = loginURI.protocol?.trim().toLowerCase() === 'https:';

        const port = loginURI.port ?? secure ? '443' : '80';

        const secureClientOptions = {
            host: loginURI.hostname,
            port: parseInt(port, 10),
            path: loginURI.path,
            rejectUnauthorized: false
        };
        const client = (secure) ? xmlrpc.createSecureClient(secureClientOptions) : xmlrpc.createClient(secureClientOptions);
        client.methodCallAsync = util.promisify(client.methodCall);

        const value = await client.methodCallAsync('login_to_simulator',
            [
                {
                    'first': params.firstName,
                    'last': params.lastName,
                    'passwd': '$1$' + crypto.createHash('md5').update(params.password.substr(0, 16)).digest('hex'),
                    'start': params.start,
                    'major': '0',
                    'minor': '0',
                    'patch': '1',
                    'build': '0',
                    'platform': 'win',
                    'mac': LoginHandler.GenerateMAC(),
                    'viewer_digest': uuid.v4(),
                    'user_agent': 'nmv',
                    'author': 'tom@caspertech.co.uk',
                    'options': [
                        'inventory-root',
                        'inventory-skeleton',
                        'inventory-lib-root',
                        'inventory-lib-owner',
                        'inventory-skel-lib',
                        'gestures',
                        'event_categories',
                        'event_notifications',
                        'classified_categories',
                        'buddy-list',
                        'ui-config',
                        'login-flags',
                        'global-textures'
                    ]
                }
            ]);

        if (!value['login'] || value['login'] === 'false') throw new Error(value['message']);
        
        return value;
    }

}
