import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { BigNumber } from 'bignumber.js';
import { from, Observable } from 'rxjs';
import { filter, flatMap, share, startWith, toArray } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { TokenPipe } from '../../pipes/token.pipe';
import { IdenticonCacheService } from '../../services/identicon-cache.service';

import { RaidenService } from '../../services/raiden.service';

export interface PaymentDialogPayload {
    tokenAddress: string;
    targetAddress: string;
    amount: number;
    decimals: number;
}

@Component({
    selector: 'app-payment-dialog',
    templateUrl: './payment-dialog.component.html',
    styleUrls: ['./payment-dialog.component.css']
})
export class PaymentDialogComponent implements OnInit {

    public form: FormGroup;

    public token: FormControl;
    public targetAddress: FormControl;
    public amount: FormControl;

    public filteredOptions$: Observable<UserToken[]>;
    public tokenPipe: TokenPipe;
    private tokens$: Observable<UserToken[]>;

    private _decimals = 0;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: PaymentDialogPayload,
        public dialogRef: MatDialogRef<PaymentDialogComponent>,
        private raidenService: RaidenService,
        private identiconCacheService: IdenticonCacheService,
        private fb: FormBuilder
    ) {
        this.tokenPipe = new TokenPipe();
        this._decimals = this.data.decimals;
    }

    ngOnInit() {
        const data = this.data;
        const raidenAddress = this.raidenService.raidenAddress;

        this.form = this.fb.group({
            target_address: [data.targetAddress, (control) => control.value === raidenAddress ? {ownAddress: true} : undefined],
            token: data.tokenAddress,
            amount: [0]
        });

        this.token = this.form.get('token') as FormControl;
        this.targetAddress = this.form.get('target_address') as FormControl;
        this.amount = this.form.get('amount') as FormControl;

        this.tokens$ = this.raidenService.getTokens(true).pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => !!token.connected),
            toArray(),
            share()
        );

        this.filteredOptions$ = this.form.controls['token'].valueChanges.pipe(
            startWith(''),
            flatMap(value => this._filter(value))
        );
    }

    public step(): string {
        return (1 / (10 ** this._decimals)).toFixed(this._decimals).toString();
    }

    public decimals(): number {
        return this._decimals;
    }

    public precise(value) {
        if (value.type === 'input' && !value.inputType) {
            this.amount.setValue(new BigNumber(value.target.value).toFixed(this._decimals));
        }
    }

    public accept() {
        const value = this.form.value;

        const payload: PaymentDialogPayload = {
            tokenAddress: value['token'],
            targetAddress: value['target_address'],
            decimals: this._decimals,
            amount: value['amount']
        };

        this.dialogRef.close(payload);
    }

    public reset() {
        this.form.reset();

        const tokenAddress = this.data.tokenAddress;
        const targetAddress = this.data.targetAddress;

        if (tokenAddress) {
            this.token.setValue(tokenAddress);
        }

        this.targetAddress.setValue(targetAddress ? targetAddress : '');
        this.amount.setValue(0);
        this._decimals = this.data.decimals;
    }

    // noinspection JSMethodCanBeStatic
    identicon(address?: string): string {
        if (!address) {
            return '';
        }
        return this.identiconCacheService.getIdenticon(address);
    }

    // noinspection JSMethodCanBeStatic
    trackByFn(token: UserToken): string {
        return token.address;
    }

    private _filter(value?: string): Observable<UserToken[]> {
        if (!value || typeof value !== 'string') {
            return this.tokens$;
        }

        const keyword = value.toLowerCase();
        return this.tokens$.pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => {
                const name = token.name.toLocaleLowerCase();
                const symbol = token.symbol.toLocaleLowerCase();
                const address = token.address.toLocaleLowerCase();
                return name.startsWith(keyword) || symbol.startsWith(keyword) || address.startsWith(keyword);
            }),
            toArray()
        );
    }

    tokenSelected(value: UserToken) {
        this._decimals = value.decimals;
        this.token.setValue(value.address);
    }
}
