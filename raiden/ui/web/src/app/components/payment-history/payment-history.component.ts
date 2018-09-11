import { animate, state, style, transition, trigger } from '@angular/animations';
import { Component, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { MatPaginator, PageEvent } from '@angular/material';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { BehaviorSubject, Observable, Subscription } from 'rxjs';
import { concatMap, flatMap, map, share, tap } from 'rxjs/operators';
import { PaymentEvent } from '../../models/payment-event';
import { UserToken } from '../../models/usertoken';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';

interface PaymentHistoryParameters {
    readonly tokenAddress: string;
    readonly partnerAddress: string;
    readonly token: UserToken;
}

@Component({
    selector: 'app-payment-history',
    templateUrl: './payment-history.component.html',
    styleUrls: ['./payment-history.component.css'],
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
export class PaymentHistoryComponent implements OnInit, OnDestroy {

    @ViewChild(MatPaginator) paginator: MatPaginator;
    readonly partnerInformation$: Observable<PaymentHistoryParameters>;
    pageSize = 10;
    private readonly history$: Observable<PaymentEvent[]>;
    private subject: BehaviorSubject<void> = new BehaviorSubject(null);
    private currentPage = 0;
    private subscription: Subscription;
    private _allHistory: PaymentEvent[] = [];

    constructor(
        private route: ActivatedRoute,
        private raidenService: RaidenService,
        private raidenConfig: RaidenConfig,
        private indenticonCache: IdenticonCacheService
    ) {
        this.partnerInformation$ = this.route.queryParamMap.pipe(
            concatMap((params: ParamMap) => {
                const tokenAddress = params.get('token_address');
                const partnerAddress = params.get('partner_address');

                return this.raidenService.getUserToken(tokenAddress).pipe(map(value => ({
                    tokenAddress: tokenAddress,
                    partnerAddress: partnerAddress,
                    token: value
                })));
            }),
            tap(x => this._decimals = x.token.decimals),
            share()
        );

        let timeout;
        this.history$ = this.subject.pipe(
            tap(() => clearTimeout(timeout)),
            flatMap(() => this.partnerInformation$.pipe(
                flatMap(value => this.raidenService.getPaymentHistory(value.tokenAddress, value.partnerAddress)),
            )),
            tap(() => {
                timeout = setTimeout(() => this.refresh(), this.raidenConfig.config.poll_interval);
            })
        );
    }

    private _decimals = 0;

    public get decimals(): number {
        return this._decimals;
    }

    private _length: number;

    public get length(): number {
        return this._length;
    }

    private _visibleHistory: PaymentEvent[] = [];

    public get visibleHistory(): PaymentEvent[] {
        return this._visibleHistory;
    }

    private _isLoading = true;

    public get isLoading(): boolean {
        return this._isLoading;
    }

    ngOnInit() {
        this.subscription = this.history$.subscribe(value => {
            this._allHistory = value;
            this._isLoading = false;
            this.showPage();
        });
    }

    ngOnDestroy(): void {
        this.subscription.unsubscribe();
    }

    onPageEvent(event: PageEvent) {
        this.currentPage = event.pageIndex;
        this.pageSize = event.pageSize;
        this.showPage();
    }

    // noinspection JSMethodCanBeStatic
    trackByFn(event: PaymentEvent) {
        return event.identifier;
    }

    // noinspection JSMethodCanBeStatic
    normalizeEvent(event: string): string {
        return event.replace('EventPayment', '')
            .replace('Success', '')
            .replace('Failed', '')
            .trim();
    }

    // noinspection JSMethodCanBeStatic
    isFailure(event: string): boolean {
        return event.toLowerCase().indexOf('failed') > 0;
    }

    identicon(address: string) {
        return this.indenticonCache.getIdenticon(address);
    }

    private showPage() {
        this._length = this._allHistory.length;
        const start = this.pageSize * this.currentPage;
        const end = start + this.pageSize;
        this._visibleHistory = this._allHistory.concat()
            .reverse()
            .slice(start, end);
    }

    private refresh() {
        this.subject.next(null);
    }
}
