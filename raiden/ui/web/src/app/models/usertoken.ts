import { Connection } from './connection';

export interface UserToken {
    address: string;
    symbol: string;
    name: string;
    decimals: number;
    balance: number;
    connected?: Connection;
}
