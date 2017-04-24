import { Injectable } from '@angular/core';
import { Subject } from 'rxjs/Subject';
import { Channel } from '../models/channel';

@Injectable()
export class SharedService {

    private channelsSubject = new Subject<Channel[]>();
    public channelsObservable$ = this.channelsSubject.asObservable();

    public setChannelData(channels: Channel[]) {
        console.log('Calling Setchannel Data' + channels);
        this.channelsSubject.next(channels);
    }

}
