import { Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { from, Observable } from 'rxjs';
import { filter, flatMap, toArray } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenService } from '../../services/raiden.service';
import { AddressInputComponent } from '../address-input/address-input.component';
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
export class OpenDialogComponent  {

    public form: FormGroup = this.fb.group({
        address: '',
        token: '',
        amount: 0,
        settle_timeout: [500, (control) => control.value > 0 ? undefined : {invalidAmount: true}]
    });

    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;
    @ViewChild(AddressInputComponent) addressInput: AddressInputComponent;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: OpenDialogPayload,
        public dialogRef: MatDialogRef<OpenDialogComponent>,
        public raidenService: RaidenService,
        private identiconCacheService: IdenticonCacheService,
        private fb: FormBuilder,
    ) {
    }

    accept() {
        const value = this.form.value;
        const result: OpenDialogResult = {
            tokenAddress: value.token,
            partnerAddress: value.address,
            settleTimeout: value.settle_timeout,
            balance: this.tokenInput.tokenAmount.toNumber(),
            decimals: this.tokenInput.tokenAmountDecimals
        };

        this.dialogRef.close(result);
    }

    tokenNetworkSelected(value: UserToken) {
        this.tokenInput.decimals = value.decimals;
    }
}
