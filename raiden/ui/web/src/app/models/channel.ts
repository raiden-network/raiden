import { UserToken } from './usertoken';

export interface Channel {
    channel_identifier: number;
    token_address: string;
    partner_address: string;
    state: string;
    total_deposit: number;
    balance: number;
    settle_timeout: number;
    reveal_timeout: number;
    userToken: UserToken | null;
}
