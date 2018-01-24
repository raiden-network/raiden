export interface Event {
    event_type: string;
    block_number: number;
    timestamp?: Date;
    token_address?: string;
    channel_manager_address?: string;
    settle_timeout?: number;
    netting_channel?: string;
    participant1?: string;
    participant2?: string;
    participant?: string;
    balance?: number;
    identifier?: number;
    data?: string;
}

export interface EventsParam {
    channel?: string;
    token?: string;
    activity?: boolean;
}
