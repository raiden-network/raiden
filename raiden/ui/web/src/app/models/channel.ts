export interface Channel {
    channel_identifier: string;
    token_address: string;
    partner_address: string;
    state: string;
    balance: number;
    settle_timeout: number;
    reveal_timeout: number;
}
