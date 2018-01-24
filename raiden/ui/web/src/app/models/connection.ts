export interface Connection {
    funds: number;
    sum_deposits: number;
    channels: number;
}

export interface Connections {
    [address: string]: Connection;
}
