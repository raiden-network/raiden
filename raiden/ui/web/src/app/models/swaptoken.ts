export interface SwapToken {
    partner_address: string;
    identifier: string;
    role: string;
    sending_token: string;
    sending_amount: number;
    receiving_token: string;
    receiving_amount: number;
}
