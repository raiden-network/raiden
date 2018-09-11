import { Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { UserToken } from '../../models/usertoken';
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

    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: PaymentDialogPayload,
        public dialogRef: MatDialogRef<PaymentDialogComponent>,
        private raidenService: RaidenService,
        private identiconCacheService: IdenticonCacheService,
        private fb: FormBuilder
    ) {

    }

    ngOnInit() {
        const data = this.data;
        this.tokenInput.decimals = data.decimals;

        const raidenAddress = this.raidenService.raidenAddress;

        this.form = this.fb.group({
            target_address: [data.targetAddress, (control) => control.value === raidenAddress ? {ownAddress: true} : undefined],
            amount: 0,
            token: data.tokenAddress
        });
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
            amount: 0
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

    tokenNetworkSelected(token: UserToken) {
        this.tokenInput.decimals = token.decimals;
    }
}
