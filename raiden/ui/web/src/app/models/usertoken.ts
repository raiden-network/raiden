import { Connection } from './connection';

export interface Usertoken {
    address: string;
    symbol: string;
    name: string;
    balance: number;
    connected?: Connection;
}
