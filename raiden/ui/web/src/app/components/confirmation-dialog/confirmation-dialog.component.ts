import { Component, Inject, OnInit } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';

export interface ConfirmationDialogPayload {
    title: string;
    message: string;
}

@Component({
    selector: 'app-confirmation-dialog',
    templateUrl: './confirmation-dialog.component.html',
    styleUrls: ['./confirmation-dialog.component.css']
})
export class ConfirmationDialogComponent implements OnInit {
    readonly title: string;
    readonly message: string;

    constructor(
        @Inject(MAT_DIALOG_DATA) public payload: ConfirmationDialogPayload,
        public dialogRef: MatDialogRef<ConfirmationDialogComponent>
    ) {
        this.title = this.payload.title;
        this.message = this.payload.message;
    }

    ngOnInit() {
    }

    confirm() {
        this.dialogRef.close(true);
    }

}
