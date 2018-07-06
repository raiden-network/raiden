import { BehaviorSubject } from 'rxjs';
import { scan } from 'rxjs/operators';
import { Injectable } from '@angular/core';
import { HttpRequest } from '@angular/common/http';
import { Message } from 'primeng/primeng';

import { Channel } from '../models/channel';


@Injectable()
export class SharedService {

    public httpTimeout: number;
    public messages: Message[] = [];

    private requestsSubject = new BehaviorSubject<number>(0);
    public readonly requests$ = this.requestsSubject.asObservable().pipe(
        scan((acc, value) => Math.max(acc + value, 0), 0),
    );

    public msg(message: Message) {
        this.messages = [...this.messages, message];
    }

    public cleanMessages() {
        this.messages = [];
    }

    requestStarted(req?: HttpRequest<any>) {
        this.requestsSubject.next(+1);
    }

    requestFinished(req?: HttpRequest<any>) {
        this.requestsSubject.next(-1);
    }

}
