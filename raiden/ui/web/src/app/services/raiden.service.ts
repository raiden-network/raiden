import { Injectable } from '@angular/core';
import { Http, Headers, RequestOptions, Response } from '@angular/http';
import { Observable } from 'rxjs/Observable';
import { RaidenConfig } from './raiden.config';
import { tokenabi } from './tokenabi';
import { Usertoken } from '../models/usertoken';
import { Channel } from '../models/channel';
import { Event, EventsParam } from '../models/event';
import { SharedService } from './shared.service';

@Injectable()
export class RaidenService {

    public tokenContract: any;
    public web3: any;
    public raidenAddress: string;
    private userTokens: { [id: string]: Usertoken |null} = {};

    constructor(private http: Http,
        private config: RaidenConfig,
        private sharedService: SharedService) {
        this.web3 = this.config.web3;
        this.tokenContract = this.web3.eth.contract(tokenabi);
    }

    public getRaidenAddress(): Observable<string> {
        return this.http.get(`${this.config.apiCall}/address`)
            .map((response) => this.raidenAddress = response.json().our_address)
            .catch((error) => this.handleError(error));
    }

    public getChannels(): Observable<Channel[]> {
        return this.http.get(`${this.config.apiCall}/channels`)
            .map((response) => <Channel[]>response.json())
            .catch((error) => this.handleError(error));
    }

    public getTokensBalances(refresh: boolean = true): Observable<Usertoken[]> {
        return this.http.get(`${this.config.apiCall}/tokens`)
            .map((response) => {
                const tokenArray: Array<{ address: string }> = response.json();
                return tokenArray
                    .map((tokeninfo) => this.getUsertoken(tokeninfo.address, refresh))
                    .filter((u) => u !== null);
            })
            .catch((error) => this.handleError(error));
    }

    public openChannel(
        partnerAddress: string,
        tokenAddress: string,
        balance: number,
        settleTimeout: number): Observable<any> {
        console.log('Inside the open channel service');
        const data = {
            'partner_address': partnerAddress,
            'token_address': tokenAddress,
            'balance': balance,
            'settle_timeout': settleTimeout
        };
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        return this.http.put(`${this.config.apiCall}/channels`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));

    }

    public initiateTransfer(
        tokenAddress: string,
        partnerAddress: string,
        amount: number,
        identifier: number): Observable<any> {
        const data = {
            'amount': amount,
            'identifier': identifier
        };
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        console.log(`${this.config.apiCall}/transfers/${tokenAddress}/${partnerAddress}`);
        return this.http.post(`${this.config.apiCall}/transfers/${tokenAddress}/${partnerAddress}`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));
    }

    public depositToChannel(channelAddress: string, balance: number): Observable<any> {
        const data = {
            'balance': balance
        };
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        return this.http.patch(`${this.config.apiCall}/channels/${channelAddress}`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));
    }

    public closeChannel(channelAddress: string): Observable<any> {
        const data = {
            'state': 'closed'
        };
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        return this.http.patch(`${this.config.apiCall}/channels/${channelAddress}`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));
    }

    public settleChannel(channelAddress: string): Observable<any> {
        const data = {
            'state': 'settled'
        };
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        return this.http.patch(`${this.config.apiCall}/channels/${channelAddress}`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));
    }

    public registerToken(tokenAddress: string): Observable<Usertoken> {
        return this.http.put(`${this.config.apiCall}/tokens/${tokenAddress}`, '{}')
            .map(() => {
                this.tokenContract = this.web3.eth.contract(tokenabi);
                const userToken: Usertoken | null = this.getUsertoken(tokenAddress);
                if (!userToken) {
                    throw new Error('No contract on address: ' + tokenAddress);
                }
                return <Usertoken>userToken;
            })
            .catch((error) => this.handleError(error));
    }

    public connectTokenNetwork(funds: number, tokenAddress: string): Observable<any> {
        const data = {
            'funds': funds
        }
        const headers = new Headers({ 'Content-Type': 'application/json' });
        const options = new RequestOptions({ headers: headers });
        return this.http.put(`${this.config.apiCall}/connection/${tokenAddress}`,
            JSON.stringify(data), options)
            .map((response) => response.json())
            .catch((error) => this.handleError(error));
    }

    public getEvents(
        eventsParam: EventsParam,
        fromBlock?: number | undefined): Observable<Event[]> {
        let path: string;
        if (eventsParam.channel) {
            path = `channels/${eventsParam.channel}`;
        } else if (eventsParam.token) {
            path = `tokens/${eventsParam.token}`;
        } else {
            path = 'network';
        }
        if (fromBlock) {
            path += `?from_block=${fromBlock}`;
        }
        return this.http.get(`${this.config.apiCall}/events/${path}`)
            .map((response) => <Event[]>response.json())
            .catch((error) => this.handleError(error));
    }

    private getUsertoken(tokenAddress: string, refresh: boolean = true): Usertoken |null {
        const tokenContractInstance = this.tokenContract.at(tokenAddress);
        let userToken: Usertoken |null| undefined = this.userTokens[tokenAddress];
        if (userToken === undefined) {
            let name: string = null;
            let symbol: string = null;
            try {
                symbol = tokenContractInstance.symbol();
            } catch (e) { }
            try {
                name = tokenContractInstance.name();
            } catch (e) { }
            try {
                userToken = {
                    address: tokenAddress,
                    symbol,
                    name,
                    balance: tokenContractInstance.balanceOf(this.raidenAddress).toNumber(),
                };
            } catch (e) {
                userToken = null;
            }
            this.userTokens[tokenAddress] = userToken;
        } else if (refresh && userToken !== null) {
            userToken.balance = tokenContractInstance.balanceOf(this.raidenAddress).toNumber();
        }
        return userToken;
    }

    private handleError(error: Response | any) {
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
        this.sharedService.msg({
            severity: 'error',
            summary: 'Raiden Error',
            detail: JSON.stringify(errMsg),
        });
        return Observable.throw(errMsg);
    }

}
