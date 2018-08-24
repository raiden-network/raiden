import { Injectable } from '@angular/core';
import makeBlockie from 'ethereum-blockies-base64';

@Injectable({
    providedIn: 'root'
})
export class IdenticonCacheService {

    private cache: { [id: string]: string } = {};

    constructor() {
    }

    public getIdenticon(address: string): string {
        const cached = this.cache[address];

        if (!cached) {
            const generated = makeBlockie(address);
            this.cache[address] = generated;
            return generated;
        } else {
            return cached;
        }
    }

}
