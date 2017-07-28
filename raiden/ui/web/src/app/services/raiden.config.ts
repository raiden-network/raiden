import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
declare var Web3;

@Injectable()
export class RaidenConfig {
    public config: { raiden: string, web3: string };
    public api: string;
    public web3: any;

    constructor(private http: Http) { }

    load(url: string) {
        return new Promise((resolve) => {
            this.http.get(url)
                .map((response) => response.json())
                .subscribe((config: { raiden: string, web3: string }) => {
                    this.config = config;
                    this.api = config.raiden;
                    if (this.web3) {
                        this.web3 = new Web3(this.web3.currentProvider);
                    } else {
                        this.web3 = new Web3(new Web3.providers.HttpProvider(config.web3));
                    }
                    resolve();
                });
        });
    }
}
