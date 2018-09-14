import { Component, OnDestroy, OnInit } from '@angular/core';
import { default as makeBlockie } from 'ethereum-blockies-base64';
import { Subscription } from 'rxjs';
import { ChannelPollingService } from './services/channel-polling.service';
import { RaidenService } from './services/raiden.service';
import { SharedService } from './services/shared.service';

@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.css'],
})
export class AppComponent implements OnInit, OnDestroy {
    public title = 'Raiden';
    public raidenAddress;

    pendingRequests = 0;
    private sub: Subscription;

    constructor(
        private sharedService: SharedService,
        private raidenService: RaidenService,
        private channelPollingService: ChannelPollingService
    ) {
    }

    ngOnInit() {
        this.raidenService.raidenAddress$.subscribe((address) => this.raidenAddress = address);
        this.sub = this.sharedService.pendingRequests.subscribe((pendingRequests) => {
            setTimeout(() => {
                this.pendingRequests = pendingRequests;
            });
        });
        const pollingSubscription = this.channelPollingService.channels().subscribe();
        this.sub.add(pollingSubscription);
    }

    ngOnDestroy() {
        this.sub.unsubscribe();
    }

    // noinspection JSMethodCanBeStatic
    identicon(address: string): string {
        if (address) {
            return makeBlockie(address);
        } else {
            return '';
        }

    }
}
