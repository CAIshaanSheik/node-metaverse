// This file has been automatically generated by writeMessageClasses.js

import { UUID } from '../UUID';
import { MessageFlags } from '../../enums/MessageFlags';
import { MessageBase } from '../MessageBase';
import { Message } from '../../enums/Message';

export class AvatarPickerRequestBackendMessage implements MessageBase
{
    name = 'AvatarPickerRequestBackend';
    messageFlags = MessageFlags.Trusted | MessageFlags.FrequencyLow;
    id = Message.AvatarPickerRequestBackend;

    AgentData: {
        AgentID: UUID;
        SessionID: UUID;
        QueryID: UUID;
        GodLevel: number;
    };
    Data: {
        Name: Buffer;
    };

    getSize(): number
    {
        return (this.Data['Name'].length + 1) + 49;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        this.AgentData['AgentID'].writeToBuffer(buf, pos);
        pos += 16;
        this.AgentData['SessionID'].writeToBuffer(buf, pos);
        pos += 16;
        this.AgentData['QueryID'].writeToBuffer(buf, pos);
        pos += 16;
        buf.writeUInt8(this.AgentData['GodLevel'], pos++);
        buf.writeUInt8(this.Data['Name'].length, pos++);
        this.Data['Name'].copy(buf, pos);
        pos += this.Data['Name'].length;
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const newObjAgentData: {
            AgentID: UUID,
            SessionID: UUID,
            QueryID: UUID,
            GodLevel: number
        } = {
            AgentID: UUID.zero(),
            SessionID: UUID.zero(),
            QueryID: UUID.zero(),
            GodLevel: 0
        };
        newObjAgentData['AgentID'] = new UUID(buf, pos);
        pos += 16;
        newObjAgentData['SessionID'] = new UUID(buf, pos);
        pos += 16;
        newObjAgentData['QueryID'] = new UUID(buf, pos);
        pos += 16;
        newObjAgentData['GodLevel'] = buf.readUInt8(pos++);
        this.AgentData = newObjAgentData;
        const newObjData: {
            Name: Buffer
        } = {
            Name: Buffer.allocUnsafe(0)
        };
        varLength = buf.readUInt8(pos++);
        newObjData['Name'] = buf.slice(pos, pos + varLength);
        pos += varLength;
        this.Data = newObjData;
        return pos - startPos;
    }
}

