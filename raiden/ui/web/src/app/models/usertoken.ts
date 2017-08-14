import { MenuItem } from 'primeng/primeng';

export interface Usertoken {
    address: string;
    symbol: string;
    name: string;
    balance: number;
    channelCnt?: number;
    menu?: MenuItem[];
};
