export interface Channel {
    channel_address: string;
    partner_address: string;
    token_address: string;
    state: string;
    balance: number;
    settle_timeout: number;
    reveal_timeout: number;
}
