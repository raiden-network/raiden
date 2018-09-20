import { animate, state, style, transition, trigger } from '@angular/animations';
import { Component, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { MatDialog, MatPaginator, PageEvent } from '@angular/material';
import { EMPTY, Subscription } from 'rxjs';
import { Observable } from 'rxjs/internal/Observable';
import { flatMap } from 'rxjs/operators';
import { Channel } from '../../models/channel';
import { SortingData } from '../../models/sorting.data';
import { ChannelPollingService } from '../../services/channel-polling.service';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { amountToDecimal } from '../../utils/amount.converter';
import { StringUtils } from '../../utils/string.utils';
import { ConfirmationDialogComponent, ConfirmationDialogPayload } from '../confirmation-dialog/confirmation-dialog.component';
import { DepositDialogComponent, DepositDialogPayload, DepositDialogResult } from '../deposit-dialog/deposit-dialog.component';
import { OpenDialogComponent, OpenDialogPayload, OpenDialogResult } from '../open-dialog/open-dialog.component';
import { PaymentDialogComponent, PaymentDialogPayload } from '../payment-dialog/payment-dialog.component';
import { ChannelSorting } from './channel.sorting.enum';

@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
    animations: [
        trigger('flyInOut', [
            state('in', style({opacity: 1, transform: 'translateX(0)'})),
            transition('void => *', [
                style({
                    opacity: 0,
                    transform: 'translateX(+100%)'
                }),
                animate('0.2s ease-in')
            ]),
            transition('* => void', [
                animate('0.2s 0.1s ease-out', style({
                    opacity: 0,
                    transform: 'translateX(100%)'
                }))
            ])
        ])
    ]
})
export class ChannelTableComponent implements OnInit, OnDestroy {

    @ViewChild(MatPaginator) paginator: MatPaginator;

    public channels$: Observable<Channel[]>;
    public amount: number;

    visibleChannels: Channel[] = [];
    totalChannels = 0;


    pageSize = 10;
    sorting = ChannelSorting.Balance;
    filter = '';
    ascending = false;

    sortingOptions: SortingData[] = [
        {
            value: ChannelSorting.Channel,
            label: 'Channel'
        },
        {
            value: ChannelSorting.Partner,
            label: 'Partner'
        },
        {
            value: ChannelSorting.Token,
            label: 'Token'
        },
        {
            value: ChannelSorting.Balance,
            label: 'Balance'
        },
        {
            value: ChannelSorting.State,
            label: 'State'
        }
    ];

    refreshing$ = this.channelPollingService.refreshing();

    private currentPage = 0;
    private channels: Channel[];
    private subscription: Subscription;

    constructor(
        public dialog: MatDialog,
        private raidenConfig: RaidenConfig,
        private raidenService: RaidenService,
        private channelPollingService: ChannelPollingService,
        private identiconCacheService: IdenticonCacheService
    ) {
    }

    ngOnInit() {
        this.channels$ = this.channelPollingService.channels();
        this.subscription = this.channels$.subscribe((channels: Channel[]) => {
            this.channels = channels;
            this.totalChannels = channels.length;
            this.applyFilters(this.sorting);
        });

        this.refresh();
    }

    ngOnDestroy() {
        this.subscription.unsubscribe();

    }

    onPageEvent(event: PageEvent) {
        this.currentPage = event.pageIndex;
        this.pageSize = event.pageSize;
    }

    changeOrder() {
        this.ascending = !this.ascending;
        this.applyFilters(this.sorting);
    }

    applyKeywordFilter() {
        this.applyFilters(this.sorting);
        this.paginator.firstPage();
    }

    clearFilter() {
        this.filter = '';
        this.applyFilters(this.sorting);
        this.paginator.firstPage();
    }

    // noinspection JSMethodCanBeStatic
    trackByFn(index, item: Channel) {
        return item.channel_identifier;
    }

    // noinspection JSMethodCanBeStatic
    identicon(channel: Channel): string {
        return this.identiconCacheService.getIdenticon(channel.partner_address);
    }

    public onPay(channel: Channel) {

        const payload: PaymentDialogPayload = {
            tokenAddress: channel.token_address,
            targetAddress: channel.partner_address,
            amount: this.amount,
            decimals: channel.userToken.decimals
        };

        const dialog = this.dialog.open(PaymentDialogComponent, {
            width: '500px',
            data: payload
        });

        dialog.afterClosed().pipe(
            flatMap((result?: PaymentDialogPayload) => {
                if (!result) {
                    return EMPTY;
                }

                return this.raidenService.initiatePayment(
                    result.tokenAddress,
                    result.targetAddress,
                    result.amount,
                    result.decimals
                );
            })
        ).subscribe(() => this.refresh());
    }

    public onDeposit(channel: Channel) {
        const payload: DepositDialogPayload = {
            decimals: channel.userToken.decimals
        };

        const dialog = this.dialog.open(DepositDialogComponent, {
            width: '500px',
            data: payload
        });

        dialog.afterClosed().pipe(
            flatMap((deposit?: DepositDialogResult) => {
                if (!deposit) {
                    return EMPTY;
                }

                return this.raidenService.depositToChannel(
                    channel.token_address,
                    channel.partner_address,
                    deposit.tokenAmount,
                    deposit.tokenAmountDecimals
                );
            })
        ).subscribe(() => this.refresh());
    }

    public onClose(channel: Channel) {

        const payload: ConfirmationDialogPayload = {
            title: 'Close Channel',
            message: `Are you sure you want to close channel ${channel.channel_identifier}<br/>` +
                `with <b>${channel.partner_address}</b><br/> on <b>${channel.userToken.name}<b/> (${channel.userToken.address})`
        };

        const dialog = this.dialog.open(ConfirmationDialogComponent, {
            width: '500px',
            data: payload
        });

        dialog.afterClosed().pipe(
            flatMap(result => {
                if (!result) {
                    return EMPTY;
                }

                return this.raidenService.closeChannel(
                    channel.token_address,
                    channel.partner_address,
                );
            })
        ).subscribe(() => this.refresh());
    }

    public onOpenChannel() {

        const rdnConfig = this.raidenConfig.config;

        const payload: OpenDialogPayload = {
            ownAddress: this.raidenService.raidenAddress,
            revealTimeout: rdnConfig.reveal_timeout,
            defaultSettleTimeout: rdnConfig.settle_timeout
        };

        const dialog = this.dialog.open(OpenDialogComponent, {
            width: '500px',
            data: payload
        });

        dialog.afterClosed().pipe(
            flatMap((result: OpenDialogResult) => {
                if (!result) {
                    return EMPTY;
                }

                return this.raidenService.openChannel(
                    result.tokenAddress,
                    result.partnerAddress,
                    result.settleTimeout,
                    result.balance,
                    result.decimals
                );
            })).subscribe(() => this.refresh());
    }

    applyFilters(sorting: ChannelSorting) {
        const channels: Array<Channel> = this.channels;
        let compareFn: (a: Channel, b: Channel) => number;

        const compareNumbers: (ascending: boolean, a: number, b: number) => number = ((ascending, a, b) => {
            return this.ascending ? a - b : b - a;
        });

        switch (sorting) {
            case ChannelSorting.State:
                compareFn = (a, b) => StringUtils.compare(this.ascending, a.state, b.state);
                break;
            case ChannelSorting.Token:
                compareFn = (a, b) => StringUtils.compare(this.ascending, a.token_address, b.token_address);
                break;
            case ChannelSorting.Partner:
                compareFn = (a, b) => StringUtils.compare(this.ascending, a.partner_address, b.partner_address);
                break;
            case ChannelSorting.Channel:
                compareFn = (a, b) => compareNumbers(this.ascending, a.channel_identifier, b.channel_identifier);
                break;
            default:
                compareFn = (a, b) => {
                    const aBalance = amountToDecimal(a.balance, a.userToken.decimals);
                    const bBalance = amountToDecimal(b.balance, b.userToken.decimals);
                    return compareNumbers(this.ascending, aBalance, bBalance);
                };
                break;
        }

        const start = this.pageSize * this.currentPage;

        const filteredChannels = channels.filter((value: Channel) => this.searchFilter(value));

        this.totalChannels = this.filter ? filteredChannels.length : this.channels.length;

        this.visibleChannels = filteredChannels
            .sort(compareFn)
            .slice(start, start + this.pageSize);
    }

    private refresh() {
        this.channelPollingService.refresh();
    }

    private searchFilter(channel: Channel): boolean {
        const searchString = this.filter.toLocaleLowerCase();
        const identifier = channel.channel_identifier.toString();
        const partner = channel.partner_address.toLocaleLowerCase();
        const tokenAddress = channel.token_address.toLocaleLowerCase();
        const channelState = channel.state.toLocaleLowerCase();
        const tokenName = channel.userToken.name.toLocaleLowerCase();
        const tokenSymbol = channel.userToken.symbol.toLocaleLowerCase();

        return identifier.startsWith(searchString) ||
            partner.startsWith(searchString) ||
            tokenAddress.startsWith(searchString) ||
            channelState.startsWith(searchString) ||
            tokenName.startsWith(searchString) ||
            tokenSymbol.startsWith(searchString);
    }
}
