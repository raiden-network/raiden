import { Component, forwardRef, Input } from '@angular/core';
import {
    AbstractControl,
    ControlValueAccessor,
    FormControl,
    NG_VALIDATORS,
    NG_VALUE_ACCESSOR,
    ValidationErrors,
    Validator,
    ValidatorFn
} from '@angular/forms';
import { IdenticonCacheService } from '../../services/identicon-cache.service';
import { RaidenService } from '../../services/raiden.service';

@Component({
    selector: 'app-address-input',
    templateUrl: './address-input.component.html',
    styleUrls: ['./address-input.component.css'],
    providers: [
        {
            provide: NG_VALUE_ACCESSOR,
            useExisting: forwardRef(() => AddressInputComponent),
            multi: true
        },
        {
            provide: NG_VALIDATORS,
            useExisting: forwardRef(() => AddressInputComponent),
            multi: true
        }
    ]
})
export class AddressInputComponent implements ControlValueAccessor, Validator {

    @Input() placeholder: string;
    @Input() errorPlaceholder: string;
    @Input() displayIdenticon = false;

    readonly addressFc = new FormControl('', [this.addressValidatorFn(this.raidenService)]);

    constructor(
        private identiconCacheService: IdenticonCacheService,
        private raidenService: RaidenService
    ) {
    }

    // noinspection JSMethodCanBeStatic
    identicon(address: string): string {
        return this.identiconCacheService.getIdenticon(address);
    }

    registerOnChange(fn: any): void {
        this.addressFc.valueChanges.subscribe(fn);
    }

    registerOnTouched(fn: any): void {
        this.addressFc.registerOnChange(fn);
    }

    setDisabledState(isDisabled: boolean): void {
        isDisabled ? this.addressFc.disable() : this.addressFc.enable();
    }

    writeValue(obj: any): void {
        if (!obj) {
            return;
        }
        this.addressFc.setValue(obj, {emitEvent: false});
    }

    checksum(): string {
        return this.raidenService.toChecksumAddress(this.addressFc.value);
    }

    registerOnValidatorChange(fn: () => void): void {

    }

    validate(c: AbstractControl): ValidationErrors | null {
        if (!this.addressFc.value) {
            return {empty: true};
        }
        return this.addressFc.errors;
    }

    private addressValidatorFn(raidenService: RaidenService): ValidatorFn {
        return (control: AbstractControl) => {
            const controlValue = control.value;
            if (controlValue === raidenService.raidenAddress) {
                return {ownAddress: true};
            } else if (controlValue && controlValue.length === 42 && !raidenService.checkChecksumAddress(controlValue)) {
                return {notChecksumAddress: true};
            } else {
                return undefined;
            }
        };
    }
}
