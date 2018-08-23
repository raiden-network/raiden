import { Directive, Input } from '@angular/core';
import { AbstractControl, NG_VALIDATORS, ValidationErrors, Validator } from '@angular/forms';
import { BigNumber } from 'bignumber.js';

@Directive({
    selector: '[appAllowedDecimals]',
    providers: [{provide: NG_VALIDATORS, useExisting: AllowedDecimalsDirective, multi: true}]
})
export class AllowedDecimalsDirective implements Validator {

    @Input('appAllowedDecimals') allowedDecimals: number;

    constructor() {
    }

    registerOnValidatorChange(fn: () => void): void {
    }

    validate(control: AbstractControl): ValidationErrors | null {
        const value = control.value;

        if (value > 0) {
            const decimalPlaces = new BigNumber(value).decimalPlaces();

            if (decimalPlaces > this.allowedDecimals) {
                return {
                    tooManyDecimals: true
                };
            }
            return undefined;
        } else {
            return {
                invalidAmount: true
            };
        }
    }

}
