import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/map';
import 'rxjs/add/observable/throw';
import 'rxjs/add/operator/catch';
import { RaidenConfig } from './raiden.config';
import { tokenabi } from './tokenabi';
import { Usertoken } from '../models/usertoken';

@Injectable()
export class RaidenService {

    public tokenContract: any;
    public web3; any;
    public raidenAddress: string;
    constructor(private http: Http, private config: RaidenConfig) {
        this.web3 = this.config.web3;
        this.tokenContract = this.web3.eth.contract(tokenabi);
        this.raidenAddress = this.web3.eth.coinbase;
    }

    public getChannels(): Observable<any> {
        console.log(this.raidenAddress);
        return this.http.get(this.config.apiCall + '/channels')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getEvents(): Observable<any> {
        return this.http.get(this.config.apiCall + '/events')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getTradedTokens(): Observable<any> {
        return this.http.get(this.config.apiCall + '/tokens')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getTokenBalancesOf(raidenAddress: string): Observable<any> {
        return this.http.get(this.config.apiCall + '/tokens')
        .map((response) => {
            const data = response.json();
            console.log(data);
            return data.map((tokeninfo) => {
                const tokenContractInstance = this.tokenContract.at(tokeninfo.address);
                return new Usertoken(
                tokeninfo.address,
                tokenContractInstance.symbol(),
                tokenContractInstance.name(),
                tokenContractInstance.balanceOf(this.raidenAddress));
            });
        }).catch(this.handleError);
    }

    private handleError (error: Response | any) {
        // In a real world app, you might use a remote logging infrastructure
        let errMsg: string;
        if (error instanceof Response) {
          const body = error.json() || '';
          const err = body || JSON.stringify(body);
          errMsg = `${error.status} - ${error.statusText || ''} ${err}`;
        } else {
          errMsg = error.message ? error.message : error.toString();
        }
        console.error(errMsg);
        return Observable.throw(errMsg);
    }

}
