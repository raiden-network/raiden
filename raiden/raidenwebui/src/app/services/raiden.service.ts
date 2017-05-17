import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/map';
import 'rxjs/add/observable/throw';
import 'rxjs/add/operator/catch';
import { RaidenConfig } from './raiden.config';

@Injectable()
export class RaidenService {

    constructor(private http: Http, private config: RaidenConfig) {
    }

    public getChannels(): Observable<any> {
        console.log(this.getRaidenAddress());
        return this.http.get(this.config.apiCall + '/channels/')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getEvents(): Observable<any> {
        return this.http.get(this.config.apiCall + '/events/')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getTradedTokens(): Observable<any> {
        return this.http.get(this.config.apiCall + '/tokens/')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getTokenBalancesOf(raidenAddress: string): Observable<any> {
        return this.http.get('/src/app/services/tokenbalance.json')
        .map((response) => response.json()).catch(this.handleError);
    }

    public getRaidenAddress() {
        const web3 = this.config.getWeb3();
        return web3.eth.coinbase;
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
