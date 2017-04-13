export class Event {
    public asset: string;
    public block: number;
    public partner: string;
    public status: string;
    public timestamp: number;

    constructor(asset: string, block: number, partner: string,
                status: string, timestamp: number) {
        this.asset = asset;
        this.block = block;
        this.partner = partner;
        this.status = status;
        this.timestamp = timestamp;
    }

}
