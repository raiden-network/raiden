import { Component, Inject } from '@angular/core';
import { FormControl } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { BigNumber } from 'bignumber.js';

export interface JoinDialogPayload {
    tokenAddress: string;
    funds: number;
    decimals: number;
}

@Component({
    selector: 'app-join-dialog',
    templateUrl: './join-dialog.component.html',
    styleUrls: ['./join-dialog.component.css']
})
export class JoinDialogComponent {

    private _decimals = 0;
    public funds: FormControl = new FormControl(0);

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: JoinDialogPayload,
        public dialogRef: MatDialogRef<JoinDialogComponent>
    ) {
        this._decimals = data.decimals;
    }

    public joinTokenNetwork() {
        const payload: JoinDialogPayload = {
            tokenAddress: this.data.tokenAddress,
            funds: this.funds.value,
            decimals: this._decimals
        };
        this.dialogRef.close(payload);
    }

    public step(): string {
        return (1 / (10 ** this._decimals)).toFixed(this._decimals).toString();
    }

    public decimals(): number {
        return this._decimals;
    }

    public precise(value) {
        if (value.type === 'input' && !value.inputType) {
            this.funds.setValue(new BigNumber(value.target.value).toFixed(this._decimals));
        }
    }

}
