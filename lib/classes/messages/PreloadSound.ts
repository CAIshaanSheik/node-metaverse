// This file has been automatically generated by writeMessageClasses.js

import {UUID} from '../UUID';
import {MessageFlags} from '../../enums/MessageFlags';
import {MessageBase} from '../MessageBase';
import {Message} from '../../enums/Message';

export class PreloadSoundMessage implements MessageBase
{
    name = 'PreloadSound';
    messageFlags = MessageFlags.Trusted | MessageFlags.FrequencyMedium;
    id = Message.PreloadSound;

    DataBlock: {
        ObjectID: UUID;
        OwnerID: UUID;
        SoundID: UUID;
    }[];

    getSize(): number
    {
        return ((48) * this.DataBlock.length) + 1;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        const count = this.DataBlock.length;
        buf.writeUInt8(this.DataBlock.length, pos++);
        for (let i = 0; i < count; i++)
        {
            this.DataBlock[i]['ObjectID'].writeToBuffer(buf, pos);
            pos += 16;
            this.DataBlock[i]['OwnerID'].writeToBuffer(buf, pos);
            pos += 16;
            this.DataBlock[i]['SoundID'].writeToBuffer(buf, pos);
            pos += 16;
        }
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const count = buf.readUInt8(pos++);
        this.DataBlock = [];
        for (let i = 0; i < count; i++)
        {
            const newObjDataBlock: {
                ObjectID: UUID,
                OwnerID: UUID,
                SoundID: UUID
            } = {
                ObjectID: UUID.zero(),
                OwnerID: UUID.zero(),
                SoundID: UUID.zero()
            };
            newObjDataBlock['ObjectID'] = new UUID(buf, pos);
            pos += 16;
            newObjDataBlock['OwnerID'] = new UUID(buf, pos);
            pos += 16;
            newObjDataBlock['SoundID'] = new UUID(buf, pos);
            pos += 16;
            this.DataBlock.push(newObjDataBlock);
        }
        return pos - startPos;
    }
}
