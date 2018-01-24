import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import { SharedService } from './shared.service';

declare var Web3;

interface RDNConfig {
    raiden: string;
    web3: string;
    web3_fallback?: string;
    poll_interval?: number;
    block_start?: number;
    http_timeout?: number;
}

const default_config: RDNConfig = {
    raiden: '/api/1',
    web3: '/web3',
    web3_fallback: 'http://localhost:8545',
    poll_interval: 5000,
    block_start: 1603031,
    http_timeout: 600000,
};

@Injectable()
export class RaidenConfig {
    public config: RDNConfig = default_config;
    public api: string;
    public web3: any;

    constructor(private http: HttpClient,
                private sharedService: SharedService) { }

    load(url: string) {
        return new Promise((resolve) => {
            this.http.get<RDNConfig>(url)
                .subscribe((config) => {
                    this.config = Object.assign({}, default_config, config);
                    this.api = this.config.raiden;
                    this.web3 = new Web3(new Web3.providers.HttpProvider(this.config.web3, 2000));
                    // make a simple test call to web3
                    this.web3.version.getNetwork((err, res) => {
                        if (err) {
                            console.error('Invalid web3 endpoint', err);
                            console.log('Switching to fallback: ' + this.config.web3_fallback);
                            this.config.web3 = this.config.web3_fallback;
                            this.web3 = new Web3(new Web3.providers.HttpProvider(this.config.web3));
                        } else {
                            // on success, reconstruct without timeout,
                            // because of long (events) running requests
                            this.web3 = new Web3(new Web3.providers.HttpProvider(this.config.web3));
                        }
                        this.sharedService.httpTimeout = this.config.http_timeout;
                        resolve();
                    });
                });
        });
    }
}
