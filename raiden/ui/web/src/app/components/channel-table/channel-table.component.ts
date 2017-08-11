import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs/Observable';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Channel } from '../../models/channel';
import { EventsParam } from '../../models/event';
import { MenuItem, Message, SelectItem } from 'primeng/primeng';

declare var blockies;
const INTERVAL = 5000;

@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
})
export class ChannelTableComponent implements OnInit {

    public channels$: Observable<Channel[]>;
    public amount: number;
    public displayDialog: boolean;
    public displayChannelDialog: boolean;
    public action: string;
    public tempChannel: Channel = {};
    public tokenAddressMapping$: Observable<SelectItem[]>;
    public watchEvents: EventsParam[] = [{}];
    public tabIndex = 0;

    constructor(private raidenService: RaidenService,
                private sharedService: SharedService) { }

    ngOnInit() {
        this.tokenAddressMapping$ = this.raidenService.getTokensBalances(false)
            .map((userTokens) => userTokens.map((userToken) =>
                ({
                    value: userToken.address,
                    label: userToken.name + ' (' + userToken.address + ')',
                }))
            );

        this.channels$ = Observable.timer(0, INTERVAL)
            .switchMap(() => this.raidenService.getChannels())
            .scan((oldChannels, newChannels) => {
                // use scan and Object.assign to keep object references and
                // improve *ngFor change detection on data table
                for (const newchannel of newChannels) {
                    const oldchannel = oldChannels.find((c) =>
                        c.channel_address === newchannel.channel_address);
                    if (oldchannel) {
                        Object.assign(oldchannel, newchannel);
                    } else {
                        oldChannels.push(Object.assign(newchannel, { menu: this.menuFor(newchannel) }));
                    }
                }
                return oldChannels.filter((oldchannel) =>
                    newChannels.find((c) => c.channel_address === oldchannel.channel_address));
            }, []);
    }

    public generateBlockies(icon: any, address: string) {
        console.log(address);
        icon.style.backgroundImage = 'url(' + blockies.create({ seed: address, size: 8, scale: 16 })
            .toDataURL() + ')';
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

    public onOpen() {
        this.action = 'open';
        this.tempChannel = {};
        this.displayChannelDialog = true;
    }

    public manageChannel() {
        this.displayDialog = false;
        this.displayChannelDialog = false;
        switch (this.action) {
            case 'transfer':
                console.log('Inside Manage Channel TRansfer');
                this.raidenService.initiateTransfer(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                    this.amount)
                    .subscribe(
                        (response) => {
                            this.showMessage(response);
                        }
                    );
                break;
            case 'deposit':
                this.raidenService.depositToChannel(
                    this.tempChannel.channel_address,
                    this.amount).subscribe((response) => {
                        this.showMessage(response);
                    });
                break;
            case 'close':
                this.raidenService.closeChannel(this.tempChannel.channel_address)
                    .subscribe((response) => {
                        this.showMessage(response);
                    });
                break;
            case 'settle':
                this.raidenService.settleChannel(this.tempChannel.channel_address)
                    .subscribe((response) => {
                        this.showMessage(response);
                    });
                break;
            case 'open':
                console.log('inside open');
                this.raidenService.openChannel(
                    this.tempChannel.partner_address,
                    this.tempChannel.token_address,
                    this.tempChannel.balance,
                    this.tempChannel.settle_timeout)
                    .subscribe((response) => {
                        console.log('logging the response');
                        console.log(response);
                        this.showMessage(response);
                    });
                break;
        }
    }

    public showMessage(response: any) {
        switch (this.action) {
            case 'open':
                if ('channel_address' in response) {
                    this.sharedService.msg({
                        severity: 'info', summary: this.action,
                        detail: `Channel with address ${response.channel_address} has been
                    created with partner ${response.partner_address}`
                    });
                } else {

                }
                break;
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
        }

    }

    public menuFor(channel: Channel): MenuItem[] {
        return [
            { label: 'Transfer', icon: 'fa-exchange', command: () => this.onTransfer(channel) },
            { label: 'Deposit', icon: 'fa-money', command: () => this.onDeposit(channel) },
            { label: 'Close', icon: 'fa-close', command: () => this.onClose(channel) },
            { label: 'Settle', icon: 'fa-book', command: () => this.onSettle(channel) },
            { label: 'Watch Events', icon: 'fa-clock-o', command: () => this.watchChannelEvents(channel) },
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
