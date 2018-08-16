import { Injectable } from '@angular/core';
import { from, Subscription } from 'rxjs';
import { flatMap, scan } from 'rxjs/operators';
import { Channel } from '../models/channel';
import { ChannelPollingService } from './channel-polling.service';
import { SharedService } from './shared.service';

@Injectable({
    providedIn: 'root'
})
export class BalanceCheckerService {
    private subscription: Subscription;

    constructor(
        private channelPollingService: ChannelPollingService,
        private sharedService: SharedService
    ) {
    }

    public startMonitoring() {
        const checkForUpdatedBalance = scan((oldChannels: Channel[], newChannels: Channel[]) => {
            this.checkForBalanceChanges(oldChannels, newChannels);
            this.checkForNewChannels(oldChannels, newChannels);
            return newChannels;
        }, []);
        this.subscription = this.channelPollingService.channels()
            .pipe(checkForUpdatedBalance, flatMap(value => from(value)))
            .subscribe();
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
            if (newChannel.balance <= oldChannel.balance) {
                continue;
            }
            this.informAboutBalanceUpdate(newChannel, oldChannel.balance);
        }
    }

    public stopMonitoring() {
        this.subscription.unsubscribe();
    }

    private isTheSameChannel(channel1: Channel, channel2: Channel): boolean {
        return channel1.channel_identifier === channel2.channel_identifier;
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
        this.sharedService.info({
            title: 'Balance Update',
            description: `The balance of channel ${channelId} with ${partnerAddress} was updated by ${amount} ${symbol} tokens`
        });
    }
}
