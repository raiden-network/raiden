export class Channel {
    public channel_address: string;
    public partner_address: string;
    public token_address: string;
    public balance: number;
    public state: string;
    public settle_timeout: number;
    constructor(channel_address?: string, partner_address?: string, token_address?: string,
    balance?: number, state?: string, settle_timeout?: number) {
        this.channel_address = channel_address;
        this.partner_address = partner_address;
        this.token_address = token_address;
        this.balance = balance;
        this.state = state;
        this.settle_timeout = settle_timeout;
    }

}
