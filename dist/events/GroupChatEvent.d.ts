import { UUID } from '..';
export declare class GroupChatEvent {
    groupID: UUID;
    from: UUID;
    fromName: string;
    message: string;
}
