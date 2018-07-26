import { Component, OnDestroy, OnInit } from '@angular/core';
import { MenuItem } from 'primeng/primeng';
import { BehaviorSubject } from 'rxjs/internal/BehaviorSubject';
import { Observable } from 'rxjs/internal/Observable';
import { finalize, map, scan, switchMap, tap } from 'rxjs/operators';
import { Channel } from '../../models/channel';
import { EventsParam } from '../../models/event';
import { WithMenu } from '../../models/withmenu';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';

@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
})
export class ChannelTableComponent implements OnInit, OnDestroy {
    public channels$: Observable<Array<WithMenu<Channel>>>;
    public amount: number;
    public displayDialog: boolean;
    public displayOpenChannelDialog: boolean;
    public action: string;
    public tempChannel: Channel;
    public watchEvents: EventsParam[] = [];
    public tabIndex = 0;
    private channelsSubject: BehaviorSubject<void> = new BehaviorSubject(null);

    constructor(
        private raidenConfig: RaidenConfig,
        private raidenService: RaidenService,
        private sharedService: SharedService,
    ) {
    }

    ngOnInit() {
        let timeout;
        this.channels$ = this.channelsSubject.pipe(
            tap(() => clearTimeout(timeout)),
            switchMap(() => this.raidenService.getChannels()),
            map((newChannels) => newChannels.map((newchannel) =>
            Object.assign(newchannel, {menu: null}) as WithMenu<Channel>
        )),
            scan((oldChannels, newChannels) => {
                // use scan and Object.assign to keep object references and
                // improve *ngFor change detection on data table
                for (const newChannel of newChannels) {
                    const oldChannel: WithMenu<Channel> = oldChannels.find((c) => {
                        return c.channel_identifier === newChannel.channel_identifier;
                    });

                    const menu: MenuItem[] = oldChannel && oldChannel.menu ? oldChannel.menu : this.menuFor(newChannel);

                    Object.assign(newChannel, {
                        menu: this.updateMenu(newChannel, menu)
                    });
                }
                return newChannels;
            }, []),
            tap(() =>
                timeout = setTimeout(
                    () => this.channelsSubject.next(null),
                    this.raidenConfig.config.poll_interval,
                )
            ),
        );

        this.channelsSubject.next(null);
    }

    ngOnDestroy() {
        this.channelsSubject.complete();
    }

    rowTrackBy(index: number, channel: any) {
        return channel.channel_identifier;
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

    public showOpenChannelDialog(show: boolean = true) {
        this.displayOpenChannelDialog = show;
    }

    public manageChannel() {
        this.displayDialog = false;
        switch (this.action) {
            case 'transfer':
                this.raidenService.initiateTransfer(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                    this.amount,
                ).pipe(
                    finalize(() => this.channelsSubject.next(null)),
                ).subscribe((response) => this.showMessage(response));
                break;
            case 'deposit':
                this.raidenService.depositToChannel(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                    this.amount,
                ).pipe(
                    finalize(() => this.channelsSubject.next(null)),
                ).subscribe((response) => this.showMessage(response));
                break;
            case 'close':
                this.raidenService.closeChannel(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                ).pipe(
                    finalize(() => this.channelsSubject.next(null)),
                ).subscribe((response) => this.showMessage(response));
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
                        detail: `The channel ${response.channel_identifier} has been modified with a deposit of ${response.balance}`
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
                        detail: `The channel ${response.channel_identifier} with partner
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
                        detail: `The channel ${response.channel_identifier} with partner
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
                icon: 'fa fa-exchange',
                command: () => this.onTransfer(channel)
            },
            {
                label: 'Deposit',
                icon: 'fa fa-money',
                command: () => this.onDeposit(channel)
            },
            {
                label: 'Close',
                icon: 'fa fa-close',
                command: () => this.onClose(channel)
            },
            {
                label: 'Watch Events',
                icon: 'fa fa-clock-o',
                command: () => this.watchChannelEvents(channel)
            },
        ];
    }

    public watchChannelEvents(channel: Channel) {
        let index = this.watchEvents
            .map((event) => event.channel)
            .indexOf(channel);
        if (index < 0) {
            this.watchEvents = [...this.watchEvents, {channel}];
            index = this.watchEvents.length - 1;
        }
        setTimeout(() => this.tabIndex = index + 1, 100);
    }

    public handleCloseTab($event) {
        const newEvents = this.watchEvents.filter((e, i) => i !== $event.index - 1);
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
        const index = this.watchEvents.indexOf(eventsParam);
        eventsParam.activity = !(index >= 0 && this.tabIndex - 1 === index);
    }

    private channelIsNotOpen(channel: Channel): boolean {
        return channel.state !== 'opened';
    }

    private channelCanTransfer(channel: Channel): boolean {
        return (channel.state === 'opened' && channel.balance > 0);
    }

    private updateMenu(channel: Channel, menuItems: MenuItem[]): MenuItem[] {
        if (menuItems != null) {
            menuItems[0].disabled = !this.channelCanTransfer(channel);
            menuItems[1].disabled = this.channelIsNotOpen(channel);
            menuItems[2].disabled = this.channelIsNotOpen(channel);
        }
        return menuItems;
    }
}
