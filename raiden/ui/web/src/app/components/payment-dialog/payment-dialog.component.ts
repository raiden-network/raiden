import { Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { BigNumber } from 'bignumber.js';
import { from, Observable } from 'rxjs';
import { filter, flatMap, share, startWith, toArray } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { TokenPipe } from '../../pipes/token.pipe';
import { IdenticonCacheService } from '../../services/identicon-cache.service';

import { RaidenService } from '../../services/raiden.service';
import { TokenInputComponent } from '../token-input/token-input.component';

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

    public filteredOptions$: Observable<UserToken[]>;
    public tokenPipe: TokenPipe;
    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;
    private tokens$: Observable<UserToken[]>;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: PaymentDialogPayload,
        public dialogRef: MatDialogRef<PaymentDialogComponent>,
        private raidenService: RaidenService,
        private identiconCacheService: IdenticonCacheService,
        private fb: FormBuilder
    ) {
        this.tokenPipe = new TokenPipe();
    }

    ngOnInit() {
        const data = this.data;
        this.tokenInput.decimals = data.decimals;

        const raidenAddress = this.raidenService.raidenAddress;

        this.form = this.fb.group({
            target_address: [data.targetAddress, (control) => control.value === raidenAddress ? {ownAddress: true} : undefined],
            amount: 0,
            decimals: true,
            token: data.tokenAddress
        });

        this.token = this.form.get('token') as FormControl;
        this.targetAddress = this.form.get('target_address') as FormControl;

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

    public accept() {
        const value = this.form.value;

        const payload: PaymentDialogPayload = {
            tokenAddress: value['token'],
            targetAddress: value['target_address'],
            decimals: this.tokenInput.tokenAmountDecimals,
            amount: this.tokenInput.tokenAmount.toNumber()
        };

        this.dialogRef.close(payload);
    }

    public reset() {
        this.form.reset();
        const targetAddress = this.data.targetAddress;
        const tokenAddress = this.data.tokenAddress;

        this.form.setValue({
            target_address: targetAddress ? targetAddress : '',
            token: tokenAddress || '',
            amount: 0,
            decimals: true
        });

        this.tokenInput.resetAmount();
        this.tokenInput.decimals = this.data.decimals;
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

    tokenSelected(value: UserToken) {
        this.tokenInput.decimals = value.decimals;
        this.token.setValue(value.address);
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
}
