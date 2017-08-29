import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
declare var Web3;

interface RDNConfig {
    raiden: string;
    web3: string;
};

const WEB3_FALLBACK = 'http://localhost:8545';

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
                    this.api = this.config.raiden;
                    this.web3 = new Web3(new Web3.providers.HttpProvider(this.config.web3));
                    // make a simple test call to web3
                    this.web3.version.getNetwork((err, res) => {
                        if (err) {
                            console.error('Invalid web3 endpoint', err);
                            console.info('Switching to fallback: ' + WEB3_FALLBACK);
                            this.config.web3 = WEB3_FALLBACK;
                            this.web3 = new Web3(new Web3.providers.HttpProvider(this.config.web3));
                        }
                        resolve();
                    });
                });
        });
    }
}
