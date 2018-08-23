import { Component } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { MatDialogRef } from '@angular/material';

import { RaidenService } from '../../services/raiden.service';
import { addressValidator } from '../../shared/address.validator';

@Component({
    selector: 'app-register-dialog',
    templateUrl: './register-dialog.component.html',
    styleUrls: ['./register-dialog.component.css']
})
export class RegisterDialogComponent {

    public tokenAddress: FormControl = new FormControl('',
        [
            Validators.minLength(42),
            Validators.maxLength(42),
            addressValidator()
        ]);

    constructor(
        public dialogRef: MatDialogRef<RegisterDialogComponent>,
        private raidenService: RaidenService
    ) {
    }

    public notAChecksumAddress() {
        const control = this.tokenAddress;
        const tokenAddress = control.value;

        if (control.valid && tokenAddress && tokenAddress.length > 0) {
            return !this.raidenService.checkChecksumAddress(tokenAddress);
        } else {
            return false;
        }
    }

    public convertToChecksum(): string {
        const control = this.tokenAddress;
        const tokenAddress = control.value;
        return this.raidenService.toChecksumAddress(tokenAddress);
    }

    public registerToken() {
        const tokenAddress = this.tokenAddress.value;
        if (this.tokenAddressMatchesPattern(tokenAddress)) {
            this.dialogRef.close(tokenAddress);
        }
    }

    private tokenAddressMatchesPattern(tokenAddress) {
        return tokenAddress && /^0x[0-9a-f]{40}$/i.test(tokenAddress);
    }
}
