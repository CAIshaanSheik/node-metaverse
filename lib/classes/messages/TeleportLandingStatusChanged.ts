// This file has been automatically generated by writeMessageClasses.js

import Long = require('long');
import {MessageFlags} from '../../enums/MessageFlags';
import {MessageBase} from '../MessageBase';
import {Message} from '../../enums/Message';

export class TeleportLandingStatusChangedMessage implements MessageBase
{
    name = 'TeleportLandingStatusChanged';
    messageFlags = MessageFlags.Trusted | MessageFlags.FrequencyLow;
    id = Message.TeleportLandingStatusChanged;

    RegionData: {
        RegionHandle: Long;
    };

    getSize(): number
    {
        return 8;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        buf.writeInt32LE(this.RegionData['RegionHandle'].low, pos);
        pos += 4;
        buf.writeInt32LE(this.RegionData['RegionHandle'].high, pos);
        pos += 4;
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const newObjRegionData: {
            RegionHandle: Long
        } = {
            RegionHandle: Long.ZERO
        };
        newObjRegionData['RegionHandle'] = new Long(buf.readInt32LE(pos), buf.readInt32LE(pos+4));
        pos += 8;
        this.RegionData = newObjRegionData;
        return pos - startPos;
    }
}
