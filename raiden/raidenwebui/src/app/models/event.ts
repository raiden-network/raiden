export class Event {
    constructor(public asset: string,
                public block: number,
                public partner: string,
                public status: string,
                public timestamp: number) {}

}
