import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { BigNumber } from 'bignumber.js';
import { default as makeBlockie } from 'ethereum-blockies-base64';
import { from, Observable } from 'rxjs';
import { filter, flatMap, share, startWith, takeWhile, toArray } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { RaidenService } from '../../services/raiden.service';

export class OpenDialogPayload {
    readonly ownAddress: string;

    constructor(ownAddress: string) {
        this.ownAddress = ownAddress;
    }
}

export interface OpenDialogResult {
    tokenAddress: string;
    partnerAddress: string;
    settleTimeout: number;
    balance: number;
    decimals: number;
}

@Component({
    selector: 'app-open-dialog',
    templateUrl: './open-dialog.component.html',
    styleUrls: ['./open-dialog.component.css']
})
export class OpenDialogComponent implements OnInit {

    public form: FormGroup;
    public token: FormControl;
    public partnerAddress: FormControl;
    public balance: FormControl;
    public settleTimeout: FormControl;

    public filteredOptions: Observable<UserToken[]>;
    private tokens: Observable<UserToken[]>;
    private _decimals = 0;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: OpenDialogPayload,
        public dialogRef: MatDialogRef<OpenDialogComponent>,
        public raidenService: RaidenService,
        private fb: FormBuilder,
    ) {
    }

    ngOnInit() {
        const data = this.data;
        this.form = this.fb.group({
            partner_address: ['', (control) => control.value === data.ownAddress ? {ownAddress: true} : undefined],
            token: '',
            balance: [0],
            settle_timeout: [500, (control) => control.value > 0 ? undefined : {invalidAmount: true}]
        });

        this.token = this.form.get('token') as FormControl;
        this.partnerAddress = this.form.get('partner_address') as FormControl;
        this.balance = this.form.get('balance') as FormControl;
        this.settleTimeout = this.form.get('settle_timeout') as FormControl;

        this.tokens = this.raidenService.getTokens(true).pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => !!token.connected),
            toArray(),
            share()
        );

        this.filteredOptions = this.form.controls['token'].valueChanges.pipe(
            startWith(''),
            takeWhile(value => typeof value === 'string'),
            flatMap(value => this._filter(value))
        );
    }

    accept() {
        const value = this.form.value;
        const result: OpenDialogResult = {
            tokenAddress: value.token,
            partnerAddress: value.partner_address,
            settleTimeout: value.settle_timeout,
            balance: value.balance,
            decimals: this._decimals
        };

        this.dialogRef.close(result);
    }

    public step(): string {
        return (1 / (10 ** this._decimals)).toFixed(this._decimals).toString();
    }

    public decimals(): number {
        return this._decimals;
    }

    public precise(value) {
        if (value.type === 'input' && !value.inputType) {
            this.balance.setValue(new BigNumber(value.target.value).toFixed(this._decimals));
        }
    }

    private _filter(value?: string): Observable<UserToken[]> {
        if (!value || typeof value !== 'string') {
            return this.tokens;
        }

        const keyword = value.toLowerCase();

        return this.tokens.pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => {
                const name = token.name.toLowerCase();
                const symbol = token.symbol.toLowerCase();
                const address = token.address.toLowerCase();
                return name.startsWith(keyword) || symbol.startsWith(keyword) || address.startsWith(keyword);
            }),
            toArray()
        );
    }

    // noinspection JSMethodCanBeStatic
    identicon(address?: string): string {
        if (!address) {
            return '';
        }
        return makeBlockie(address);
    }

    tokenSelected(value: UserToken) {
        this._decimals = value.decimals;
        this.token.setValue(value.address);
    }
}
