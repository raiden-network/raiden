import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { MenuItem } from 'primeng/primeng';

import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Channel } from '../../models/channel';
import { EventsParam } from '../../models/event';
import { WithMenu } from '../../models/withmenu';

@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
})
export class ChannelTableComponent implements OnInit {

    private channelsSubject: BehaviorSubject<void> = new BehaviorSubject(null);
    public channels$: Observable<Array<WithMenu<Channel>>>;
    public amount: number;
    public displayDialog: boolean;
    public displayOpenChannelDialog: boolean;
    public action: string;
    public tempChannel: Channel;
    public watchEvents: EventsParam[] = [];
    public tabIndex = 0;

    constructor(
        private raidenConfig: RaidenConfig,
        private raidenService: RaidenService,
        private sharedService: SharedService) { }

    ngOnInit() {
        let timeout;
        this.channels$ = this.channelsSubject
            .do(() => clearTimeout(timeout))
            .switchMap(() => this.raidenService.getChannels())
            .map((newChannels) => newChannels.map((newchannel) =>
                Object.assign(newchannel, { menu: null }) as WithMenu<Channel>
            ))
            .scan((oldChannels, newChannels) => {
                // use scan and Object.assign to keep object references and
                // improve *ngFor change detection on data table
                for (const newchannel of newChannels) {
                    const oldchannel: WithMenu<Channel> = oldChannels.find((c) =>
                        c.channel_address === newchannel.channel_address);
                    if (oldchannel) {
                        Object.assign(oldchannel, newchannel, { menu: oldchannel.menu });
                    } else {
                        oldChannels.push(
                            Object.assign(
                                newchannel,
                                { menu: this.menuFor(newchannel) }
                            ) as WithMenu<Channel>
                        );
                    }
                }
                return oldChannels.filter((oldchannel) =>
                    newChannels.find((c) =>
                        c.channel_address === oldchannel.channel_address)
                );
            }, [])
            .do(() => timeout = setTimeout(() => this.channelsSubject.next(null),
                this.raidenConfig.config.poll_interval));
    }

    public onTransfer(channel: Channel) {
        console.log('Transfer');
        this.action = 'transfer';
        this.tempChannel = channel;
        this.displayDialog = true;
    }

    public onDeposit(channel: Channel) {
        this.action = 'deposit';
        this.tempChannel = channel;
        this.displayDialog = true;
    }

    public onClose(channel: Channel) {
        this.action = 'close';
        this.tempChannel = channel;
        this.manageChannel();
    }

    public onSettle(channel: Channel) {
        this.action = 'settle';
        this.tempChannel = channel;
        this.manageChannel();
    }

    public showOpenChannelDialog(show: boolean = true) {
        this.displayOpenChannelDialog = show;
    }

    public manageChannel() {
        this.displayDialog = false;
        switch (this.action) {
            case 'transfer':
                console.log('Inside Manage Channel TRansfer');
                this.raidenService.initiateTransfer(
                        this.tempChannel.token_address,
                        this.tempChannel.partner_address,
                        this.amount
                    )
                    .finally(() => this.channelsSubject.next(null))
                    .subscribe((response) => this.showMessage(response));
                break;
            case 'deposit':
                this.raidenService.depositToChannel(
                        this.tempChannel.channel_address,
                        this.amount
                    )
                    .finally(() => this.channelsSubject.next(null))
                    .subscribe((response) => this.showMessage(response));
                break;
            case 'close':
                this.raidenService.closeChannel(this.tempChannel.channel_address)
                    .finally(() => this.channelsSubject.next(null))
                    .subscribe((response) => this.showMessage(response));
                break;
            case 'settle':
                this.raidenService.settleChannel(this.tempChannel.channel_address)
                    .finally(() => this.channelsSubject.next(null))
                    .subscribe((response) => {
                        this.showMessage(response);
                    });
                break;
            default: // this should never happen
                console.error('Invalid channel action');
        }
    }

    public showMessage(response: any) {
        switch (this.action) {
            case 'transfer':
                if ('target_address' in response && 'identifier' in response) {
                    this.sharedService.msg({
                        severity: 'info', summary: this.action,
                        detail: `A transfer of amount ${response.amount} is successful with the partner ${response.target_address}`
                    });
                } else {
                    this.sharedService.msg({
                        severity: 'error', summary: this.action,
                        detail: JSON.stringify(response)
                    });
                }
                break;
            case 'deposit':
                if ('balance' in response && 'state' in response) {
                    this.sharedService.msg({
                        severity: 'info', summary: this.action,
                        detail: `The channel ${response.channel_address} has been modified with a deposit of ${response.balance}`
                    });
                } else {
                    this.sharedService.msg({
                        severity: 'error', summary: this.action,
                        detail: JSON.stringify(response)
                    });
                }
                break;
            case 'close':
                if ('state' in response && response.state === 'closed') {
                    this.sharedService.msg({
                        severity: 'info', summary: this.action,
                        detail: `The channel ${response.channel_address} with partner
                    ${response.partner_address} has been closed successfully`
                    });
                } else {
                    this.sharedService.msg({
                        severity: 'error', summary: this.action,
                        detail: JSON.stringify(response)
                    });
                }
                break;
            case 'settle':
                if ('state' in response && response.state === 'settled') {
                    this.sharedService.msg({
                        severity: 'info', summary: this.action,
                        detail: `The channel ${response.channel_address} with partner
                    ${response.partner_address} has been settled successfully`
                    });
                } else {
                    this.sharedService.msg({
                        severity: 'error', summary: this.action,
                        detail: JSON.stringify(response)
                    });
                }
                break;
            default: // this should never happen
                console.error('Invalid showMessage action');
        }

    }

    public menuFor(channel: Channel): MenuItem[] {
        return [
            {
                label: 'Transfer',
                icon: 'fa-exchange',
                disabled: !(channel.state === 'opened' && channel.balance > 0),
                command: () => this.onTransfer(channel)
            },
            {
                label: 'Deposit',
                icon: 'fa-money',
                disabled: channel.state !== 'opened',
                command: () => this.onDeposit(channel)
            },
            {
                label: 'Close',
                icon: 'fa-close',
                disabled: channel.state !== 'opened',
                command: () => this.onClose(channel)
            },
            {
                label: 'Settle',
                icon: 'fa-book',
                disabled: channel.state !== 'closed',
                command: () => this.onSettle(channel)
            },
            {
                label: 'Watch Events',
                icon: 'fa-clock-o',
                command: () => this.watchChannelEvents(channel)
            },
        ];
    }

    public watchChannelEvents(channel: Channel) {
        let index = this.watchEvents
            .map((event) => event.channel)
            .indexOf(channel.channel_address);
        if (index < 0) {
            this.watchEvents = [...this.watchEvents, { channel: channel.channel_address }];
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
