import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { default as makeBlockie } from 'ethereum-blockies-base64';
import { from, Observable } from 'rxjs';
import { filter, flatMap, share, startWith, toArray } from 'rxjs/operators';
import { Channel } from '../../models/channel';
import { UserToken } from '../../models/usertoken';
import { TokenPipe } from '../../pipes/token.pipe';

import { RaidenService } from '../../services/raiden.service';

export interface PaymentDialogPayload {
    tokenAddress: string;
    targetAddress: string;
    amount: number;
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

    public filteredOptions: Observable<UserToken[]>;
    public tokenPipe: TokenPipe;
    private tokens: Observable<UserToken[]>;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: PaymentDialogPayload,
        public dialogRef: MatDialogRef<PaymentDialogComponent>,
        private raidenService: RaidenService,
        private fb: FormBuilder
    ) {
        this.tokenPipe = new TokenPipe();
    }

    ngOnInit() {
        const data = this.data;
        const raidenAddress = this.raidenService.raidenAddress;

        this.form = this.fb.group({
            target_address: [data.targetAddress, (control) => control.value === raidenAddress ? {ownAddress: true} : undefined],
            token: data.tokenAddress,
            amount: [0, (control) => control.value > 0 ? undefined : {invalidAmount: true}]
        });

        this.token = this.form.get('token') as FormControl;
        this.targetAddress = this.form.get('target_address') as FormControl;
        this.amount = this.form.get('amount') as FormControl;

        this.tokens = this.raidenService.getTokens().pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => !!token.connected),
            toArray(),
            share()
        );

        this.filteredOptions = this.form.controls['token'].valueChanges.pipe(
            startWith(''),
            flatMap(value => this._filter(value))
        );
    }

    public accept() {
        const value = this.form.value;

        const payload: PaymentDialogPayload = {
            tokenAddress: value['token'],
            targetAddress: value['target_address'],
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
    }

    // noinspection JSMethodCanBeStatic
    identicon(address?: string): string {
        if (!address) {
            return '';
        }
        return makeBlockie(address);
    }

    private _filter(value: string): Observable<UserToken[]> {
        const keyword = value.toLowerCase();
        return this.tokens.pipe(
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
