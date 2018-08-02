import { Component } from '@angular/core';
import { FormControl, FormGroupDirective, NgForm } from '@angular/forms';
import { ErrorStateMatcher, MatDialogRef } from '@angular/material';

import { RaidenService } from '../../services/raiden.service';

export class InvalidTokenErrorStateMatcher implements ErrorStateMatcher {

    constructor(private raidenService: RaidenService) {
    }

    isErrorState(control: FormControl | null, form: FormGroupDirective | NgForm | null): boolean {
        const isSubmitted = form && form.submitted;
        const isValidChecksum = control.value ? this.raidenService.checkChecksumAddress(control.value) : false;
        return !!(control && control.invalid && (control.dirty || control.touched || isSubmitted) && !isValidChecksum);
    }
}

@Component({
    selector: 'app-register-dialog',
    templateUrl: './register-dialog.component.html',
    styleUrls: ['./register-dialog.component.css']
})
export class RegisterDialogComponent {

    public tokenAddressControl: FormControl = new FormControl();
    public tokenAddress = '';

    invalidTokenErrorStateMatcher = new InvalidTokenErrorStateMatcher(this.raidenService);

    constructor(
        public dialogRef: MatDialogRef<RegisterDialogComponent>,
        private raidenService: RaidenService
    ) {
    }

    public notAChecksumAddress() {
        const formControl = this.tokenAddressControl;
        const tokenAddress = formControl.value;

        if (formControl.valid && tokenAddress && tokenAddress.length > 0) {
            return !this.raidenService.checkChecksumAddress(tokenAddress);
        } else {
            return false;
        }
    }

    public convertToChecksum(): string {
        return this.raidenService.toChecksumAddress(this.tokenAddress);
    }

    public registerToken() {
        const tokenAddress = this.tokenAddressControl.value;
        if (this.tokenAddressMatchesPattern(tokenAddress)) {
            this.dialogRef.close(tokenAddress);
        }
    }

    private tokenAddressMatchesPattern(tokenAddress) {
        return tokenAddress && /^0x[0-9a-f]{40}$/i.test(tokenAddress);
    }
}
