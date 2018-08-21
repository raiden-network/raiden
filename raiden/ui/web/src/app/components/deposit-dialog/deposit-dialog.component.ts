import { Component, Inject, OnInit } from '@angular/core';
import { FormControl } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { BigNumber } from 'bignumber.js';

export interface DepositDialogPayload {
    decimals: number;
}

@Component({
    selector: 'app-deposit-dialog',
    templateUrl: './deposit-dialog.component.html',
    styleUrls: ['./deposit-dialog.component.css']
})
export class DepositDialogComponent implements OnInit {

    public depositControl: FormControl = new FormControl(0);
    private readonly _decimals;

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: DepositDialogPayload,
        public dialogRef: MatDialogRef<DepositDialogComponent>
    ) {
        this._decimals = data.decimals;
    }

    ngOnInit() {
    }

    deposit() {
        const deposit = this.depositControl.value as number;
        this.dialogRef.close(deposit);
    }

    public step(): string {
        return (1 / (10 ** this._decimals)).toFixed(this._decimals).toString();
    }

    public decimals(): number {
        return this._decimals;
    }

    public precise(value) {
        if (value.type === 'input' && !value.inputType) {
            this.depositControl.setValue(new BigNumber(value.target.value).toFixed(this._decimals));
        }
    }

}
