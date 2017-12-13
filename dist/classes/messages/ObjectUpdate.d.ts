/// <reference types="long" />
/// <reference types="node" />
import { UUID } from '../UUID';
import { Vector3 } from '../Vector3';
import Long = require('long');
import { MessageBase } from '../MessageBase';
import { Message } from '../../enums/Message';
export declare class ObjectUpdateMessage implements MessageBase {
    name: string;
    messageFlags: number;
    id: Message;
    RegionData: {
        RegionHandle: Long;
        TimeDilation: number;
    };
    ObjectData: {
        ID: number;
        State: number;
        FullID: UUID;
        CRC: number;
        PCode: number;
        Material: number;
        ClickAction: number;
        Scale: Vector3;
        ObjectData: Buffer;
        ParentID: number;
        UpdateFlags: number;
        PathCurve: number;
        ProfileCurve: number;
        PathBegin: number;
        PathEnd: number;
        PathScaleX: number;
        PathScaleY: number;
        PathShearX: number;
        PathShearY: number;
        PathTwist: number;
        PathTwistBegin: number;
        PathRadiusOffset: number;
        PathTaperX: number;
        PathTaperY: number;
        PathRevolutions: number;
        PathSkew: number;
        ProfileBegin: number;
        ProfileEnd: number;
        ProfileHollow: number;
        TextureEntry: Buffer;
        TextureAnim: Buffer;
        NameValue: Buffer;
        Data: Buffer;
        Text: Buffer;
        TextColor: Buffer;
        MediaURL: Buffer;
        PSBlock: Buffer;
        ExtraParams: Buffer;
        Sound: UUID;
        OwnerID: UUID;
        Gain: number;
        Flags: number;
        Radius: number;
        JointType: number;
        JointPivot: Vector3;
        JointAxisOrAnchor: Vector3;
    }[];
    getSize(): number;
    calculateVarVarSize(block: object[], paramName: string, extraPerVar: number): number;
    writeToBuffer(buf: Buffer, pos: number): number;
    readFromBuffer(buf: Buffer, pos: number): number;
}