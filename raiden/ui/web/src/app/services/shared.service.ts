import { Injectable } from '@angular/core';
import { Subject } from 'rxjs/Subject';
import { Channel } from '../models/channel';
import { Message } from 'primeng/primeng';


@Injectable()
export class SharedService {

    private channelsSubject = new Subject<Channel[]>();
    public channelsObservable$ = this.channelsSubject.asObservable();

    public messages: Message[] = [];

    public setChannelData(channels: Channel[]) {
        console.log('Calling Setchannel Data' + channels);
        this.channelsSubject.next(channels);
    }

    public msg(message: Message) {
        this.messages = [...this.messages, message];
    }

    public cleanMessages() {
        this.messages = [];
    }

}
