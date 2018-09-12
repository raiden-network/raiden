import { ChangeDetectorRef, Component, Inject, OnInit, ViewChild } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { TokenInputComponent } from '../token-input/token-input.component';

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
export class JoinDialogComponent implements OnInit {

    @ViewChild(TokenInputComponent) tokenInput: TokenInputComponent;

    form = this.fb.group({
        amount: 0
    });

    constructor(
        @Inject(MAT_DIALOG_DATA) public data: JoinDialogPayload,
        public dialogRef: MatDialogRef<JoinDialogComponent>,
        private fb: FormBuilder,
        private cdRef: ChangeDetectorRef,
    ) {
    }

    ngOnInit(): void {
        this.tokenInput.decimals = this.data.decimals;
        this.cdRef.detectChanges();
    }

    public joinTokenNetwork() {
        const payload: JoinDialogPayload = {
            tokenAddress: this.data.tokenAddress,
            funds: this.tokenInput.tokenAmount.toNumber(),
            decimals: this.tokenInput.tokenAmountDecimals
        };
        this.dialogRef.close(payload);
    }
}
