import { Component, OnInit } from '@angular/core';
import { FormControl } from '@angular/forms';
import { MatDialogRef } from '@angular/material';

@Component({
    selector: 'app-deposit-dialog',
    templateUrl: './deposit-dialog.component.html',
    styleUrls: ['./deposit-dialog.component.css']
})
export class DepositDialogComponent implements OnInit {

    public depositControl: FormControl = new FormControl(null,
        (control) => control.value > 0 ? undefined : {
            invalidFund: true
        });

    constructor(
        public dialogRef: MatDialogRef<DepositDialogComponent>
    ) {
    }

    ngOnInit() {
    }

    deposit() {
        const deposit = this.depositControl.value as number;
        this.dialogRef.close(deposit);
    }

}
