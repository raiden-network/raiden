import { Injectable } from '@angular/core';
import { Subject } from 'rxjs/Subject';
import { Channel } from '../models/channel';
import { Message } from 'primeng/primeng';


@Injectable()
export class SharedService {

    public messages: Message[] = [];

    public msg(message: Message) {
        this.messages = [...this.messages, message];
    }

    public cleanMessages() {
        this.messages = [];
    }

}
