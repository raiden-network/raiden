import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { share, switchMap, tap } from 'rxjs/operators';
import { Channel } from '../models/channel';
import { RaidenConfig } from './raiden.config';
import { RaidenService } from './raiden.service';

@Injectable({
    providedIn: 'root'
})
export class ChannelPollingService {

    private channelsSubject: BehaviorSubject<void> = new BehaviorSubject(null);
    private refreshingSubject: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
    private readonly channels$: Observable<Channel[]>;

    constructor(
        private raidenService: RaidenService,
        private raidenConfig: RaidenConfig
    ) {
        let timeout;
        this.channels$ = this.channelsSubject.pipe(
            tap(() => {
                clearTimeout(timeout);
                this.refreshingSubject.next(true);
            }),
            switchMap(() => this.raidenService.getChannels()),
            tap(() => {
                    timeout = setTimeout(
                        () => this.refresh(),
                        this.raidenConfig.config.poll_interval,
                    );
                    this.refreshingSubject.next(false);
                }
            ),
            share()
        );

        this.refresh();
    }

    public refreshing(): Observable<boolean> {
        return this.refreshingSubject;
    }

    public channels(): Observable<Channel[]> {
        return this.channels$;
    }

    public refresh() {
        this.channelsSubject.next(null);
    }
}
