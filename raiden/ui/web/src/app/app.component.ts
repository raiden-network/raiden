import { Component, OnDestroy, OnInit } from '@angular/core';
import { default as makeBlockie } from 'ethereum-blockies-base64';
import { Subscription } from 'rxjs';
import { ChannelChecker } from './services/channel-checker.service';
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
        private balanceCheckerService: ChannelChecker
    ) {
    }

    ngOnInit() {
        this.raidenService.getRaidenAddress().subscribe((address) => this.raidenAddress = address);
        this.sub = this.sharedService.pendingRequests.subscribe((pendingRequests) => {
            setTimeout(() => {
                this.pendingRequests = pendingRequests;
            });
        });

        this.balanceCheckerService.startMonitoring();
    }

    ngOnDestroy() {
        this.balanceCheckerService.stopMonitoring();
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
