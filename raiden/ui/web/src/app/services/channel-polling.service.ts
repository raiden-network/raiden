import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { scan, share, switchMap, tap } from 'rxjs/operators';
import { Channel } from '../models/channel';
import { amountToDecimal } from '../utils/amount.converter';
import { RaidenConfig } from './raiden.config';
import { RaidenService } from './raiden.service';
import { SharedService } from './shared.service';

@Injectable({
    providedIn: 'root'
})
export class ChannelPollingService {

    private channelsSubject: BehaviorSubject<void> = new BehaviorSubject(null);
    private refreshingSubject: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
    private readonly channels$: Observable<Channel[]>;

    constructor(
        private raidenService: RaidenService,
        private sharedService: SharedService,
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
            scan((oldChannels: Channel[], newChannels: Channel[]) => {
                this.checkForBalanceChanges(oldChannels, newChannels);
                this.checkForNewChannels(oldChannels, newChannels);
                return newChannels;
            }, []),
            share()
        );
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

    private checkForNewChannels(oldChannels: Channel[], newChannels: Channel[]) {
        if (oldChannels.length > 0) {
            const channels = newChannels.filter(newChannel => {
                return !oldChannels.find(oldChannel => this.isTheSameChannel(oldChannel, newChannel));
            });

            for (const channel of channels) {
                this.informAboutNewChannel(channel);
            }
        }
    }

    private checkForBalanceChanges(oldChannels: Channel[], newChannels: Channel[]) {
        for (const oldChannel of oldChannels) {
            const newChannel = newChannels.find(channel => this.isTheSameChannel(oldChannel, channel));
            if (!newChannel || newChannel.balance <= oldChannel.balance) {
                continue;
            }
            this.informAboutBalanceUpdate(newChannel, oldChannel.balance);
        }
    }

    // noinspection JSMethodCanBeStatic
    private isTheSameChannel(channel1: Channel, channel2: Channel): boolean {
        return channel1.channel_identifier === channel2.channel_identifier && channel1.token_address === channel2.token_address;
    }

    private informAboutNewChannel(channel: Channel) {
        const channelId = channel.channel_identifier;
        const partnerAddress = channel.partner_address;
        const network = channel.userToken.name;

        this.sharedService.info({
            title: 'New channel',
            description: `A new channel: ${channelId} was opened with ${partnerAddress} on ${network}`
        });
    }

    private informAboutBalanceUpdate(channel: Channel, previousBalance: number) {
        const amount = channel.balance - previousBalance;
        const symbol = channel.userToken.symbol;
        const channelId = channel.channel_identifier;
        const partnerAddress = channel.partner_address;
        const balance = amountToDecimal(amount, channel.userToken.decimals);
        const formattedBalance = balance.toFixed(channel.userToken.decimals);
        this.sharedService.info({
            title: 'Balance Update',
            description: `The balance of channel ${channelId} with ${partnerAddress} was updated by ${formattedBalance} ${symbol} tokens`
        });
    }
}
