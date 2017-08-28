import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
declare var Web3;

interface RDNConfig {
    raiden: string;
    web3: string;
};

@Injectable()
export class RaidenConfig {
    public config: RDNConfig;
    public api: string;
    public web3: any;

    constructor(private http: HttpClient) { }

    load(url: string) {
        return new Promise((resolve) => {
            this.http.get<RDNConfig>(url)
                .subscribe((config) => {
                    this.config = config;
                    this.api = config.raiden;
                    this.web3 = new Web3(new Web3.providers.HttpProvider(config.web3));
                    resolve();
                });
        });
    }
}
