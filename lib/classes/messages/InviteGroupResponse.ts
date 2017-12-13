// This file has been automatically generated by writeMessageClasses.js

import {UUID} from '../UUID';
import {MessageFlags} from '../../enums/MessageFlags';
import {MessageBase} from '../MessageBase';
import {Message} from '../../enums/Message';

export class InviteGroupResponseMessage implements MessageBase
{
    name = 'InviteGroupResponse';
    messageFlags = MessageFlags.Trusted | MessageFlags.FrequencyLow;
    id = Message.InviteGroupResponse;

    InviteData: {
        AgentID: UUID;
        InviteeID: UUID;
        GroupID: UUID;
        RoleID: UUID;
        MembershipFee: number;
    };
    GroupData: {
        GroupLimit: number;
    };

    getSize(): number
    {
        return 72;
    }

    writeToBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        this.InviteData['AgentID'].writeToBuffer(buf, pos);
        pos += 16;
        this.InviteData['InviteeID'].writeToBuffer(buf, pos);
        pos += 16;
        this.InviteData['GroupID'].writeToBuffer(buf, pos);
        pos += 16;
        this.InviteData['RoleID'].writeToBuffer(buf, pos);
        pos += 16;
        buf.writeInt32LE(this.InviteData['MembershipFee'], pos);
        pos += 4;
        buf.writeInt32LE(this.GroupData['GroupLimit'], pos);
        pos += 4;
        return pos - startPos;
    }

    readFromBuffer(buf: Buffer, pos: number): number
    {
        const startPos = pos;
        let varLength = 0;
        const newObjInviteData: {
            AgentID: UUID,
            InviteeID: UUID,
            GroupID: UUID,
            RoleID: UUID,
            MembershipFee: number
        } = {
            AgentID: UUID.zero(),
            InviteeID: UUID.zero(),
            GroupID: UUID.zero(),
            RoleID: UUID.zero(),
            MembershipFee: 0
        };
        newObjInviteData['AgentID'] = new UUID(buf, pos);
        pos += 16;
        newObjInviteData['InviteeID'] = new UUID(buf, pos);
        pos += 16;
        newObjInviteData['GroupID'] = new UUID(buf, pos);
        pos += 16;
        newObjInviteData['RoleID'] = new UUID(buf, pos);
        pos += 16;
        newObjInviteData['MembershipFee'] = buf.readInt32LE(pos);
        pos += 4;
        this.InviteData = newObjInviteData;
        const newObjGroupData: {
            GroupLimit: number
        } = {
            GroupLimit: 0
        };
        newObjGroupData['GroupLimit'] = buf.readInt32LE(pos);
        pos += 4;
        this.GroupData = newObjGroupData;
        return pos - startPos;
    }
}
