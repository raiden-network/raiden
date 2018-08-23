import { AbstractControl, ValidatorFn } from '@angular/forms';

export function addressValidator(): ValidatorFn {
    const regex = new RegExp('^0x[0-9a-fA-F]{40}$');
    return (control: AbstractControl): { [key: string]: any } | null => {
        const value = control.value;
        if (!value) {
            return {emptyAddress: true};
        } else if (!regex.test(value)) {
            return {invalidFormat: true};
        } else {
            return null;
        }
    };
}
