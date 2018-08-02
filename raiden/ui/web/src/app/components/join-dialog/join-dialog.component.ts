import { Component, Inject } from '@angular/core';
import { FormControl } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';

export interface JoinDialogPayload {
    tokenAddress: string;
    funds: number;
}

@Component({
    selector: 'app-join-dialog',
    templateUrl: './join-dialog.component.html',
    styleUrls: ['./join-dialog.component.css']
})
export class JoinDialogComponent {

    public funds: FormControl = new FormControl(null,
        (control) => control.value > 0 ? undefined : {
            invalidFund: true
        });

    constructor(
        public dialogRef: MatDialogRef<JoinDialogComponent>,
        @Inject(MAT_DIALOG_DATA) public data: JoinDialogPayload
    ) {
    }

    public joinTokenNetwork() {
        const payload: JoinDialogPayload = {
            tokenAddress: this.data.tokenAddress,
            funds: this.funds.value
        };
        this.dialogRef.close(payload);
    }
}
