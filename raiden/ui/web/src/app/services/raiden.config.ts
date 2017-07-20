import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
declare var Web3;

@Injectable()
export class RaidenConfig {
    public config: object;
    public apiCall: string;
    public web3: any;
    constructor(private http: Http) {}

    load(url: string) {
        return new Promise((resolve) => {
            this.http.get(url).map(res => res.json())
            .subscribe(config => {
                this.config = config;
                const raidenConf = this.config['raiden'];
                this.apiCall = ['http://', raidenConf['host'], ':', raidenConf['port'],
                                '/api/', raidenConf['version']].join('');
                const web3Conf = this.config['web3'];
                if (typeof this.web3 !== 'undefined') {
                    this.web3 = new Web3(this.web3.currentProvider);
                } else {
                // set the provider you want from Web3.providers
                    const web3Url = 'http://' + web3Conf['host'] + ':' + web3Conf['port'];
                    this.web3 = new Web3(new Web3.providers.HttpProvider(web3Url));
                }
                resolve();
            });
        });
    }

    public getWeb3() {
        return this.web3;
    }
}
