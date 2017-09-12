import { Component, OnInit, Input } from '@angular/core';
import { FormControl } from '@angular/forms';
import { Observable } from 'rxjs/Observable';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { MenuItem } from 'primeng/primeng';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Usertoken } from '../../models/usertoken';
import { Message, ConfirmationService } from 'primeng/primeng';
import { EventsParam } from '../../models/event';
import { WithMenu } from '../../models/withmenu';

@Component({
    selector: 'app-token-network',
    templateUrl: './token-network.component.html',
    styleUrls: ['./token-network.component.css']
})
export class TokenNetworkComponent implements OnInit {

    @Input() raidenAddress: string;

    private tokensSubject: BehaviorSubject<void> = new BehaviorSubject(null);
    public tokensBalances$: Observable<Array<WithMenu<Usertoken>>>;
    public selectedToken: Usertoken;
    public refreshing = true;
    public watchEvents: EventsParam[] = [{}];
    public tabIndex = 0;

    public displayJoinDialog = false;
    public displayRegisterDialog = false;
    public displaySwapDialog = false;
    public displayTransferDialog = false;

    constructor(private raidenService: RaidenService,
        private sharedService: SharedService,
        private confirmationService: ConfirmationService) { }

    ngOnInit() {
        this.tokensBalances$ = this.tokensSubject
            .do(() => this.refreshing = true)
            .switchMap(() => this.raidenService.getTokens(true))
            .map((userTokens) => userTokens.map((userToken) =>
                Object.assign(
                    userToken,
                    { menu: this.menuFor(userToken) }
                ) as WithMenu<Usertoken>
            ))
            .do(() => this.refreshing = false,
                () => this.refreshing = false);
    }

    private menuFor(userToken: Usertoken): MenuItem[] {
        return [
            {
                label: 'Join Network',
                icon: 'fa-sign-in',
                command: () => this.showJoinDialog(userToken),
            },
            {
                label: 'Leave Network',
                icon: 'fa-sign-out',
                disabled: !(userToken.connected),
                command: () => this.showLeaveDialog(userToken),
            },
            {
                label: 'Transfer',
                icon: 'fa-exchange',
                disabled: !(userToken.connected && userToken.connected.sum_deposits > 0),
                command: () => this.showTransferDialog(userToken),
            },
            {
                label: 'Watch Events',
                icon: 'fa-clock-o',
                command: () => this.watchTokenEvents(userToken)
            },
        ];
    }

    public showRegisterDialog(show: boolean = true) {
        this.displayRegisterDialog = show;
    }

    public showSwapDialog(show: boolean = true) {
        this.displaySwapDialog = show;
    }

    public refreshTokens() {
        this.tokensSubject.next(null);
    }

    public showJoinDialog(userToken: Usertoken, show: boolean = true) {
        this.selectedToken = userToken;
        this.displayJoinDialog = show;
    }

    public showTransferDialog(userToken: Usertoken, show: boolean = true) {
        this.selectedToken = userToken;
        this.displayTransferDialog = show;
    }

    public showLeaveDialog(userToken: Usertoken) {
        this.confirmationService.confirm({
            header: 'Leave Token Network',
            message: `Are you sure that you want to close and settle all channels for token
            <p><strong>${userToken.name} <${userToken.address}></strong>?</p>`,
            accept: () =>
                this.raidenService.leaveTokenNetwork(userToken.address)
                    .subscribe((response) => {
                        this.sharedService.msg({
                            severity: 'success',
                            summary: 'Left Token Network',
                            detail: `Successfuly closed and settled all channels
                                in ${userToken.name} <${userToken.address}> token`,
                        });
                        this.refreshTokens();
                    })
        });
    }

    public watchTokenEvents(token: Usertoken) {
        let index = this.watchEvents
            .map((event) => event.token)
            .indexOf(token.address);
        if (index < 0) {
            this.watchEvents = [...this.watchEvents, { token: token.address }];
            index = this.watchEvents.length - 1;
        }
        setTimeout(() => this.tabIndex = index + 1, 100);
    }

    public handleCloseTab($event) {
        const newEvents = this.watchEvents.filter((e, i) =>
            i === $event.index - 1 ? false : true);
        $event.close();
        setTimeout(() => this.watchEvents = newEvents, 0);
    }

    public handleChangeTab($event) {
        if ($event.index >= 1) {
            this.watchEvents[$event.index - 1].activity = false;
        }
        this.tabIndex = $event.index;
    }

    public handleActivity(eventsParam: EventsParam) {
        const index = this.watchEvents
            .indexOf(eventsParam);
        if (index >= 0 && this.tabIndex - 1 === index) {
            eventsParam.activity = false;
        } else {
            eventsParam.activity = true;
        }
    }
}
