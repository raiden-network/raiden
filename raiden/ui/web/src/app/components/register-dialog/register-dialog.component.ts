import { Component } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { MatDialogRef } from '@angular/material';

import { RaidenService } from '../../services/raiden.service';

@Component({
    selector: 'app-register-dialog',
    templateUrl: './register-dialog.component.html',
    styleUrls: ['./register-dialog.component.css']
})
export class RegisterDialogComponent {

    readonly form = this.fb.group({
        token_address: ''
    });

    constructor(
        public dialogRef: MatDialogRef<RegisterDialogComponent>,
        private raidenService: RaidenService,
        private fb: FormBuilder
    ) {
    }

    public registerToken() {
        const tokenAddress = this.form.get('token_address').value;
        this.dialogRef.close(tokenAddress);
    }
}
