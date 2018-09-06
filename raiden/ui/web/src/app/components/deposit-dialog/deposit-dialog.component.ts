import { ChangeDetectorRef, Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { TokenInputComponent } from '../token-input/token-input.component';

export interface DepositDialogPayload {
    readonly decimals: number;
}

export interface DepositDialogResult {
    readonly tokenAmount: number;
    readonly tokenAmountDecimals: number;
}

@Component({
    selector: 'app-deposit-dialog',
    templateUrl: './deposit-dialog.component.html',
    styleUrls: ['./deposit-dialog.component.css']
})
export class DepositDialogComponent implements OnInit {

    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;

    form = this.fb.group({
        amount: 0
    });

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: DepositDialogPayload,
        public dialogRef: MatDialogRef<DepositDialogComponent>,
        private fb: FormBuilder,
        private cdRef: ChangeDetectorRef
    ) {
    }

    ngOnInit() {
        this.tokenInput.decimals = this.data.decimals;
        this.cdRef.detectChanges();
    }

    deposit() {
        const tokenInput = this.tokenInput;
        const tokenAmount = tokenInput.tokenAmount.toNumber();
        const tokenAmountDecimals = tokenInput.tokenAmountDecimals;
        this.dialogRef.close({tokenAmount, tokenAmountDecimals});
    }

}
