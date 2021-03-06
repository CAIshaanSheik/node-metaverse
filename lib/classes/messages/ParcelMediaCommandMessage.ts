// This file has been automatically generated by writeMessageClasses.js

import { MessageFlags } from '../../enums/MessageFlags';
import { MessageBase } from '../MessageBase';
import { Message } from '../../enums/Message';

export class ParcelMediaCommandMessageMessage implements MessageBase
{
    name = 'ParcelMediaCommandMessage';
    messageFlags = MessageFlags.Trusted | MessageFlags.FrequencyLow;
    id = Message.ParcelMediaCommandMessage;

    CommandBlock: {
        Flags: number;
        Command: number;
        Time: number;
    };

    getSize(): number
    {
        return 12;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        buf.writeUInt32LE(this.CommandBlock['Flags'], pos);
        pos += 4;
        buf.writeUInt32LE(this.CommandBlock['Command'], pos);
        pos += 4;
        buf.writeFloatLE(this.CommandBlock['Time'], pos);
        pos += 4;
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const newObjCommandBlock: {
            Flags: number,
            Command: number,
            Time: number
        } = {
            Flags: 0,
            Command: 0,
            Time: 0
        };
        newObjCommandBlock['Flags'] = buf.readUInt32LE(pos);
        pos += 4;
        newObjCommandBlock['Command'] = buf.readUInt32LE(pos);
        pos += 4;
        newObjCommandBlock['Time'] = buf.readFloatLE(pos);
        pos += 4;
        this.CommandBlock = newObjCommandBlock;
        return pos - startPos;
    }
}

