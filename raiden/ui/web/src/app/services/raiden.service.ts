import { Injectable, NgZone } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';

import { RaidenConfig } from './raiden.config';
import { SharedService } from './shared.service';
import { tokenabi } from './tokenabi';

import { Usertoken } from '../models/usertoken';
import { Channel } from '../models/channel';
import { Event, EventsParam } from '../models/event';
import { SwapToken } from '../models/swaptoken';
import { Connection, Connections } from '../models/connection';

type CallbackFunc = (error: Error, result: any) => void;

@Injectable()
export class RaidenService {

    public tokenContract: any;
    public raidenAddress: string;
    private userTokens: { [id: string]: Usertoken |null} = {};

    constructor(
        private http: HttpClient,
        private zone: NgZone,
        private raidenConfig: RaidenConfig,
        private sharedService: SharedService,
    ) {
        this.tokenContract = this.raidenConfig.web3.eth.contract(tokenabi);
    }

    private zoneEncap(cb: CallbackFunc): CallbackFunc {
        return (err, res) => this.zone.run(() => cb(err, res));
    }

    get identifier(): number {
        return Math.floor(Date.now() / 1000) * 1000 + Math.floor(Math.random() * 1000);
    }

    get blockNumber(): number {
        return this.raidenConfig.web3.eth.blockNumber;
    }

    getBlockNumber(): Observable<number> {
        return Observable.bindNodeCallback((cb: CallbackFunc) =>
            this.raidenConfig.web3.eth.getBlockNumber(this.zoneEncap(cb)))();
    }

    public getRaidenAddress(): Observable<string> {
        return this.http.get<{ our_address: string }>(`${this.raidenConfig.api}/address`)
            .map((data) => this.raidenAddress = data.our_address)
            .catch((error) => this.handleError(error));
    }

    public getChannels(): Observable<Array<Channel>> {
        return this.http.get<Array<Channel>>(`${this.raidenConfig.api}/channels`)
            .catch((error) => this.handleError(error));
    }

    public getTokens(refresh: boolean = false): Observable<Array<Usertoken>> {
        return this.http.get<Array<string>>(`${this.raidenConfig.api}/tokens`)
            .combineLatest(refresh ?
                this.http.get<Connections>(`${this.raidenConfig.api}/connections`) :
                Observable.of(null))
            .map(([tokenArray, connections]): Array<Observable<Usertoken>> =>
                tokenArray
                    .map((token) =>
                        this.getUsertoken(token, refresh)
                            .map((userToken) => userToken && connections ?
                                Object.assign(
                                    userToken,
                                    { connected: connections[token] }
                                ) : userToken
                            )
                    )
            )
            .switchMap((obsArray) => obsArray && obsArray.length ?
                Observable.zip(...obsArray).first() :
                Observable.of([])
            )
            .map((tokenArray) => tokenArray.filter((token) => !!token))
            .catch((error) => this.handleError(error));
    }

    public openChannel(
        partnerAddress: string,
        tokenAddress: string,
        balance: number,
        settleTimeout: number): Observable<Channel> {
        console.log('Inside the open channel service');
        const data = {
            'partner_address': partnerAddress,
            'token_address': tokenAddress,
            'balance': balance,
            'settle_timeout': settleTimeout
        };
        return this.http.put<Channel>(`${this.raidenConfig.api}/channels`, data)
            .catch((error) => this.handleError(error));
    }

    public initiateTransfer(
        tokenAddress: string,
        partnerAddress: string,
        amount: number): Observable<any> {
        const data = {
            'amount': amount,
            'identifier': this.identifier
        };
        console.log(`${this.raidenConfig.api}/transfers/${tokenAddress}/${partnerAddress}`);
        return this.http.post(`${this.raidenConfig.api}/transfers/${tokenAddress}/${partnerAddress}`, data)
            .catch((error) => this.handleError(error));
    }

    public depositToChannel(channelAddress: string, balance: number): Observable<any> {
        const data = {
            'balance': balance
        };
        return this.http.patch(`${this.raidenConfig.api}/channels/${channelAddress}`, data)
            .catch((error) => this.handleError(error));
    }

    public closeChannel(channelAddress: string): Observable<any> {
        const data = {
            'state': 'closed'
        };
        return this.http.patch(`${this.raidenConfig.api}/channels/${channelAddress}`, data)
            .catch((error) => this.handleError(error));
    }

    public settleChannel(channelAddress: string): Observable<any> {
        const data = {
            'state': 'settled'
        };
        return this.http.patch(`${this.raidenConfig.api}/channels/${channelAddress}`, data)
            .catch((error) => this.handleError(error));
    }

    public registerToken(tokenAddress: string): Observable<Usertoken> {
        return this.http.put(`${this.raidenConfig.api}/tokens/${tokenAddress}`, {})
            .switchMap(() => this.getUsertoken(tokenAddress)
                .map((userToken) => {
                    if (userToken === null) {
                        throw new Error(`No contract on address: ${tokenAddress}`);
                    }
                    return userToken;
                })
            )
            .catch((error) => this.handleError(error));
    }

    public connectTokenNetwork(funds: number, tokenAddress: string): Observable<any> {
        const data = {
            'funds': funds
        };
        return this.http.put(`${this.raidenConfig.api}/connections/${tokenAddress}`, data)
            .catch((error) => this.handleError(error));
    }

    public leaveTokenNetwork(tokenAddress: string): Observable<any> {
        return this.http.delete(`${this.raidenConfig.api}/connections/${tokenAddress}`)
            .catch((error) => this.handleError(error));
    }

    public getEvents(
        eventsParam: EventsParam,
        fromBlock?: number,
        toBlock?: number): Observable<Array<Event>> {
        let path: string;
        if (eventsParam.channel) {
            path = `channels/${eventsParam.channel}`;
        } else if (eventsParam.token) {
            path = `tokens/${eventsParam.token}`;
        } else {
            path = 'network';
        }
        let params = new HttpParams();
        if (fromBlock) {
            params = params.set('from_block', '' + fromBlock);
        }
        if (toBlock) {
            params = params.set('to_block', '' + toBlock);
        }
        return this.http.get<Array<Event>>(`${this.raidenConfig.api}/events/${path}`, { params })
            .catch((error) => this.handleError(error));
    }

    public swapTokens(swap: SwapToken): Observable<boolean> {
        const data = {
            role: swap.role,
            sending_token: swap.sending_token,
            sending_amount: swap.sending_amount,
            receiving_token: swap.receiving_token,
            receiving_amount: swap.receiving_amount,
        };
        return this.http.put(`${this.raidenConfig.api}/token_swaps/${swap.partner_address}/${swap.identifier}`,
                data, { observe: 'response'})
            .switchMap((response) => response.ok ?
                Observable.of(true) :
                Observable.throw(response.toString()))
            .catch((error) => this.handleError(error));
    }

    public sha3(data: string): string {
        return this.raidenConfig.web3.sha3(data, { encoding: 'hex' });
    }

    public blocknumberToDate(block: number): Observable<Date> {
        return Observable.bindNodeCallback((b: number, cb: CallbackFunc) =>
            this.raidenConfig.web3.eth.getBlock(b, this.zoneEncap(cb)))(block)
            .map((blk) => new Date(blk.timestamp * 1000))
            .first();
    }

    public getUsertoken(
        tokenAddress: string,
        refresh: boolean = true
    ): Observable<Usertoken | null> {
        const tokenContractInstance = this.tokenContract.at(tokenAddress);
        const userToken: Usertoken |null | undefined = this.userTokens[tokenAddress];
        if (userToken === undefined) {
            return Observable.bindNodeCallback((cb: CallbackFunc) =>
                tokenContractInstance.symbol(this.zoneEncap(cb)))()
                .catch((error) => Observable.of(null))
                .combineLatest(
                Observable.bindNodeCallback((cb: CallbackFunc) =>
                    tokenContractInstance.name(this.zoneEncap(cb)))()
                    .catch((error) => Observable.of(null)),
                Observable.bindNodeCallback((addr: string, cb: CallbackFunc) =>
                    tokenContractInstance.balanceOf(
                        addr,
                        this.zoneEncap(cb)
                    ))(this.raidenAddress)
                    .map((balance) => balance.toNumber())
                    .catch((error) => Observable.of(null))
                )
                .map(([symbol, name, balance]): Usertoken => {
                    if (balance === null) {
                        return null;
                    }
                    return {
                        address: tokenAddress,
                        symbol,
                        name,
                        balance
                    };
                })
                .do((token) => this.userTokens[tokenAddress] = token);
        } else if (refresh && userToken !== null) {
            return Observable.bindNodeCallback((addr: string, cb: CallbackFunc) =>
                tokenContractInstance.balanceOf(
                    addr,
                    this.zoneEncap(cb)
                ))(this.raidenAddress)
                .map((balance) => balance.toNumber())
                .catch((error) => Observable.of(null))
                .map((balance) => {
                    if (balance === null) {
                        return null;
                    }
                    userToken.balance = balance;
                    return userToken;
                });
        } else {
            return Observable.of(userToken);
        }
    }

    private handleError(error: Response | Error | any) {
        // In a real world app, you might use a remote logging infrastructure
        let errMsg: string;
        if (error instanceof Response) {
            let body;
            try {
                body = error.json() || '';
            } catch (e) {
                body = error.text();
            }
            const err = body || JSON.stringify(body);
            errMsg = `${error.status} - ${error.statusText || ''} ${err}`;
        } else if (error instanceof HttpErrorResponse && error.error['errors']) {
            errMsg = `${error.message} => ${error.error.errors}`;
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
