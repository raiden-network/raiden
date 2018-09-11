export interface PaymentEvent {
    readonly reason?: string;
    readonly target?: string;
    readonly initiator?: string;
    readonly event: string;
    readonly amount?: number;
    readonly identifier: number;
}
