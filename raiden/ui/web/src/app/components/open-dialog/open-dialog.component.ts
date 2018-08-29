import { Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { from, Observable } from 'rxjs';
import { filter, flatMap, share, startWith, takeWhile, toArray } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenService } from '../../services/raiden.service';
import { TokenInputComponent } from '../token-input/token-input.component';

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
    public settleTimeout: FormControl;

    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;

    public filteredOptions$: Observable<UserToken[]>;
    private tokens$: Observable<UserToken[]>;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: OpenDialogPayload,
        public dialogRef: MatDialogRef<OpenDialogComponent>,
        public raidenService: RaidenService,
        private identiconCacheService: IdenticonCacheService,
        private fb: FormBuilder,
    ) {
    }

    ngOnInit() {
        const data = this.data;
        this.form = this.fb.group({
            partner_address: ['', (control) => control.value === data.ownAddress ? {ownAddress: true} : undefined],
            token: '',
            amount: 0,
            decimals: true,
            settle_timeout: [500, (control) => control.value > 0 ? undefined : {invalidAmount: true}]
        });

        this.token = this.form.get('token') as FormControl;
        this.partnerAddress = this.form.get('partner_address') as FormControl;
        this.settleTimeout = this.form.get('settle_timeout') as FormControl;

        this.tokens$ = this.raidenService.getTokens(true).pipe(
            flatMap((tokens: UserToken[]) => from(tokens)),
            filter((token: UserToken) => !!token.connected),
            toArray(),
            share()
        );

        this.filteredOptions$ = this.form.controls['token'].valueChanges.pipe(
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
            balance: this.tokenInput.tokenAmount.toNumber(),
            decimals: this.tokenInput.tokenAmountDecimals
        };

        this.dialogRef.close(result);
    }

    // noinspection JSMethodCanBeStatic
    identicon(address?: string): string {
        if (!address) {
            return '';
        }
        return this.identiconCacheService.getIdenticon(address);
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
                const name = token.name.toLowerCase();
                const symbol = token.symbol.toLowerCase();
                const address = token.address.toLowerCase();
                return name.startsWith(keyword) || symbol.startsWith(keyword) || address.startsWith(keyword);
            }),
            toArray()
        );
    }
}
