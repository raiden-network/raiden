import { throwError, zip, of, bindNodeCallback, Observable } from 'rxjs';
import { combineLatest, tap, first, switchMap, map, catchError } from 'rxjs/operators';
import { Injectable, NgZone } from '@angular/core';
import { HttpClient, HttpParams, HttpErrorResponse } from '@angular/common/http';

import { RaidenConfig } from './raiden.config';
import { SharedService } from './shared.service';
import { tokenabi } from './tokenabi';

import { UserToken } from '../models/usertoken';
import { Channel } from '../models/channel';
import { Event, EventsParam } from '../models/event';
import { SwapToken } from '../models/swaptoken';
import { Connections } from '../models/connection';

type CallbackFunc = (error: Error, result: any) => void;

@Injectable()
export class RaidenService {

    public tokenContract: any;
    public raidenAddress: string;
    private userTokens: { [id: string]: UserToken | null} = {};

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

    getBlockNumber(): Observable<number> {
        return bindNodeCallback((cb: CallbackFunc) =>
            this.raidenConfig.web3.eth.getBlockNumber(this.zoneEncap(cb)))();
    }

    public checkChecksumAddress(address: string): boolean {
        return this.raidenConfig.web3.isChecksumAddress(address);
    }

    public toChecksumAddress(address: string): string {
        return this.raidenConfig.web3.toChecksumAddress(address);
    }

    public getRaidenAddress(): Observable<string> {
        return this.http.get<{ our_address: string }>(`${this.raidenConfig.api}/address`).pipe(
            map((data) => this.raidenAddress = data.our_address),
            catchError((error) => this.handleError(error)),
        );
    }

    public getChannels(): Observable<Array<Channel>> {
        return this.http.get<Array<Channel>>(`${this.raidenConfig.api}/channels`).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public getTokens(refresh: boolean = false): Observable<Array<UserToken>> {
        return this.http.get<Array<string>>(`${this.raidenConfig.api}/tokens`).pipe(
            combineLatest(refresh ?
                this.http.get<Connections>(`${this.raidenConfig.api}/connections`) :
                of(null)
            ),
            map(([tokenArray, connections]): Array<Observable<UserToken>> =>
                tokenArray.map((token) =>
                    this.getUserToken(token, refresh).pipe(
                        map((userToken) => userToken && connections ?
                            Object.assign(
                                userToken,
                                { connected: connections[token] }
                            ) : userToken
                        ))
                )
            ),
            switchMap((obsArray) => obsArray && obsArray.length ?
                zip(...obsArray).pipe(first()) :
                of([])
            ),
            map((tokenArray) => tokenArray.filter((token) => !!token)),
            catchError((error) => this.handleError(error)),
        );
    }

    public getChannel(tokenAddress: string, partnerAddress: string): Observable<Channel> {
        return this.http.get<Channel>(
            `${this.raidenConfig.api}/channels/${tokenAddress}/${partnerAddress}`,
        ).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public openChannel(
        tokenAddress: string,
        partnerAddress: string,
        settleTimeout: number,
        balance: number,
    ): Observable<Channel> {
        console.log('Inside the open channel service');
        const data = {
            'token_address': tokenAddress,
            'partner_address': partnerAddress,
            'settle_timeout': settleTimeout,
            'balance': balance,
        };
        return this.http.put<Channel>(`${this.raidenConfig.api}/channels`, data).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public initiateTransfer(
        tokenAddress: string,
        targetAddress: string,
        amount: number,
    ): Observable<any> {
        return this.http.post(
            `${this.raidenConfig.api}/transfers/${tokenAddress}/${targetAddress}`,
            { amount, identifier: this.identifier },
        ).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public depositToChannel(
        tokenAddress: string,
        partnerAddress: string,
        amount: number,
    ): Observable<Channel> {
        return this.getChannel(tokenAddress, partnerAddress).pipe(
            switchMap((channel) => this.http.patch<Channel>(
                `${this.raidenConfig.api}/channels/${tokenAddress}/${partnerAddress}`,
                { total_deposit: channel.balance + amount },
            )),
            catchError((error) => this.handleError(error)),
        );
    }

    public closeChannel(tokenAddress: string, partnerAddress: string): Observable<Channel> {
        return this.http.patch<Channel>(
            `${this.raidenConfig.api}/channels/${tokenAddress}/${partnerAddress}`,
            { state: 'closed' },
        ).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public registerToken(tokenAddress: string): Observable<UserToken> {
        return this.http.put(
            `${this.raidenConfig.api}/tokens/${tokenAddress}`,
            {},
        ).pipe(
            switchMap(() => this.getUserToken(tokenAddress).pipe(
                map((userToken) => {
                    if (userToken === null) {
                        throw new Error(`No contract on address: ${tokenAddress}`);
                    }
                    return userToken;
                }),
            )),
            catchError((error) => this.handleError(error))
        );
    }

    public connectTokenNetwork(funds: number, tokenAddress: string): Observable<any> {
        return this.http.put(
            `${this.raidenConfig.api}/connections/${tokenAddress}`,
            { funds },
        ).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public leaveTokenNetwork(tokenAddress: string): Observable<any> {
        return this.http.delete(`${this.raidenConfig.api}/connections/${tokenAddress}`).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public getEvents(
        eventsParam: EventsParam,
        fromBlock?: number,
        toBlock?: number,
    ): Observable<Array<Event>> {
        let path: string;
        if (eventsParam.channel) {
            path = `channels/${eventsParam.channel.token_address}/${eventsParam.channel.partner_address}`;
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
        return this.http.get<Array<Event>>(
            `${this.raidenConfig.api}/events/${path}`,
            { params }
        ).pipe(
            catchError((error) => this.handleError(error)),
        );
    }

    public swapTokens(swap: SwapToken): Observable<boolean> {
        const data = {
            role: swap.role,
            sending_token: swap.sending_token,
            sending_amount: swap.sending_amount,
            receiving_token: swap.receiving_token,
            receiving_amount: swap.receiving_amount,
        };
        return this.http.put(
            `${this.raidenConfig.api}/token_swaps/${swap.partner_address}/${swap.identifier}`,
            data,
            { observe: 'response'},
        ).pipe(
            switchMap((response) => response.ok ? of(true) : throwError(response.toString())),
            catchError((error) => this.handleError(error)),
        );
    }

    public sha3(data: string): string {
        return this.raidenConfig.web3.sha3(data, { encoding: 'hex' });
    }

    public blocknumberToDate(block: number): Observable<Date> {
        return bindNodeCallback((b: number, cb: CallbackFunc) =>
            this.raidenConfig.web3.eth.getBlock(b, this.zoneEncap(cb))
        )(block).pipe(
            map((blk) => new Date(blk.timestamp * 1000)),
            first(),
        );
    }

    public getUserToken(
        tokenAddress: string,
        refresh: boolean = true,
    ): Observable<UserToken | null> {
        const tokenContractInstance = this.tokenContract.at(tokenAddress);
        const userToken: UserToken | null | undefined = this.userTokens[tokenAddress];
        if (userToken === undefined) {
            return bindNodeCallback((cb: CallbackFunc) =>
                tokenContractInstance.symbol(this.zoneEncap(cb))
            )().pipe(
                catchError(() => of(null)),
                combineLatest(
                    bindNodeCallback((cb: CallbackFunc) =>
                        tokenContractInstance.name(this.zoneEncap(cb))
                    )().pipe(
                        catchError(() => of(null)),
                    ),
                    bindNodeCallback((addr: string, cb: CallbackFunc) =>
                        tokenContractInstance.balanceOf(addr, this.zoneEncap(cb)),
                    )(this.raidenAddress).pipe(
                        map((balance) => balance.toNumber()),
                        catchError(() => of(null)),
                    ),
                ),
                map(([symbol, name, balance]): UserToken => {
                    if (balance === null) {
                        return null;
                    }
                    return {
                        address: tokenAddress,
                        symbol,
                        name,
                        balance
                    };
                }),
                tap((token) => this.userTokens[tokenAddress] = token),
            );
        } else if (refresh && userToken !== null) {
            return bindNodeCallback((addr: string, cb: CallbackFunc) =>
                tokenContractInstance.balanceOf(addr, this.zoneEncap(cb))
            )(this.raidenAddress).pipe(
                map((balance) => balance.toNumber()),
                catchError(() => of(null)),
                map((balance) => {
                    if (balance === null) {
                        return null;
                    }
                    userToken.balance = balance;
                    return userToken;
                }),
            );
        } else {
            return of(userToken);
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
            const errors = error.error.errors;

            if (typeof errors === 'string') {
                errMsg = errors;
            } else if (typeof errors === 'object') {
                errMsg = '';

                for (const key in errors) {
                    if (errors.hasOwnProperty(key)) {
                        if (errMsg !== '') {
                            errMsg += '\n';
                        }
                        errMsg += `${key}: ${errors[key]}`;
                    }
                }

            } else {
                errMsg = errors;
            }

        } else {
            errMsg = error.message ? error.message : error.toString();
        }
        console.error(errMsg);
        this.sharedService.msg({
            severity: 'error',
            summary: 'Raiden Error',
            detail: typeof errMsg === 'string' ? errMsg : JSON.stringify(errMsg),
        });
        return throwError(errMsg);
    }

}
