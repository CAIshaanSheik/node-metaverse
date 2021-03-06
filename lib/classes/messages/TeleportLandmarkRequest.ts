// This file has been automatically generated by writeMessageClasses.js

import { UUID } from '../UUID';
import { MessageFlags } from '../../enums/MessageFlags';
import { MessageBase } from '../MessageBase';
import { Message } from '../../enums/Message';

export class TeleportLandmarkRequestMessage implements MessageBase
{
    name = 'TeleportLandmarkRequest';
    messageFlags = MessageFlags.Zerocoded | MessageFlags.FrequencyLow;
    id = Message.TeleportLandmarkRequest;

    Info: {
        AgentID: UUID;
        SessionID: UUID;
        LandmarkID: UUID;
    };

    getSize(): number
    {
        return 48;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        this.Info['AgentID'].writeToBuffer(buf, pos);
        pos += 16;
        this.Info['SessionID'].writeToBuffer(buf, pos);
        pos += 16;
        this.Info['LandmarkID'].writeToBuffer(buf, pos);
        pos += 16;
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const newObjInfo: {
            AgentID: UUID,
            SessionID: UUID,
            LandmarkID: UUID
        } = {
            AgentID: UUID.zero(),
            SessionID: UUID.zero(),
            LandmarkID: UUID.zero()
        };
        newObjInfo['AgentID'] = new UUID(buf, pos);
        pos += 16;
        newObjInfo['SessionID'] = new UUID(buf, pos);
        pos += 16;
        newObjInfo['LandmarkID'] = new UUID(buf, pos);
        pos += 16;
        this.Info = newObjInfo;
        return pos - startPos;
    }
}

