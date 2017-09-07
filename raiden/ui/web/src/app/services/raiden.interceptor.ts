import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';

import { SharedService } from './shared.service';

@Injectable()
export class RaidenInterceptor implements HttpInterceptor {

    constructor(private sharedService: SharedService) { }

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        let obs = Observable.of(true)
            .do(() => this.sharedService.requestStarted(req))
            .switchMap(() => next.handle(req));
        if (this.sharedService.httpTimeout) {
            obs = obs.timeout(this.sharedService.httpTimeout);
        }
        return obs.finally(() => this.sharedService.requestFinished(req));
    }

}
