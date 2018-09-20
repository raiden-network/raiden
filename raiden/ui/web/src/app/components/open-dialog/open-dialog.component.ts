import { Component, Inject, ViewChild } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { UserToken } from '../../models/usertoken';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenService } from '../../services/raiden.service';
import { AddressInputComponent } from '../address-input/address-input.component';
import { TokenInputComponent } from '../token-input/token-input.component';

export interface OpenDialogPayload {
    readonly ownAddress: string;
    readonly defaultSettleTimeout: number;
    readonly revealTimeout: number;
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
export class OpenDialogComponent {

    public form: FormGroup = this.fb.group({
        address: '',
        token: '',
        amount: 0,
        settle_timeout: [this.data.defaultSettleTimeout, [(control: AbstractControl) => {
            const value = parseInt(control.value, 10);
            if (isNaN(value) || value <= 0) {
                return {invalidAmount: true};
            } else {
                return undefined;
            }
        }, Validators.min(this.data.revealTimeout * 2)]]
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
