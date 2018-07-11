import { Connection } from './connection';

export interface UserToken {
    address: string;
    symbol: string;
    name: string;
    balance: number;
    connected?: Connection;
}
