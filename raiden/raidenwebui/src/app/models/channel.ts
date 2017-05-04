export class Channel {
    constructor(public channel_address?: string,
                public partner_address?: string,
                public token_address?: string,
                public balance?: number,
                public state?: string,
                public settle_timeout?: number) {}
}
