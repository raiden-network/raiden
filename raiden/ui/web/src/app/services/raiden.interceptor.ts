
import { of, Observable } from 'rxjs';

import {finalize, tap, switchMap, timeout} from 'rxjs/operators';
import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';

import { SharedService } from './shared.service';

@Injectable()
export class RaidenInterceptor implements HttpInterceptor {

    constructor(private sharedService: SharedService) { }

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        let obs = of(true).pipe(
            tap(() => this.sharedService.requestStarted(req)),
            switchMap(() => next.handle(req)),
        );
        if (this.sharedService.httpTimeout) {
            obs = obs.pipe(timeout(this.sharedService.httpTimeout));
        }
        return obs.pipe(finalize(() => this.sharedService.requestFinished(req)));
    }

}
