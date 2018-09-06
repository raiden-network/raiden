import { Component, forwardRef, Input } from '@angular/core';
import {
    AbstractControl,
    ControlValueAccessor,
    FormBuilder,
    FormControl,
    FormGroup,
    NG_VALIDATORS,
    NG_VALUE_ACCESSOR,
    ValidationErrors,
    Validator,
    ValidatorFn
} from '@angular/forms';
import { MatCheckboxChange } from '@angular/material';
import { BigNumber } from 'bignumber.js';
import { amountFromDecimal, amountToDecimal } from '../../utils/amount.converter';


@Component({
    selector: 'app-token-input',
    templateUrl: './token-input.component.html',
    styleUrls: ['./token-input.component.css'],
    providers: [
        {
            provide: NG_VALUE_ACCESSOR,
            useExisting: forwardRef(() => TokenInputComponent),
            multi: true
        },
        {
            provide: NG_VALIDATORS,
            useExisting: forwardRef(() => TokenInputComponent),
            multi: true
        }
    ]
})
export class TokenInputComponent implements ControlValueAccessor, Validator {

    @Input() placeholder: string;
    @Input() errorPlaceholder: string;

    readonly form: FormGroup = this.fb.group({
        amount: [0, this.amountValidator(() => this.tokenAmountDecimals)],
        decimals: true
    });

    private readonly inputControl: FormControl;
    private readonly checkboxControl: FormControl;

    constructor(private fb: FormBuilder) {
        this.inputControl = this.form.get('amount') as FormControl;
        this.checkboxControl = this.form.get('decimals') as FormControl;
    }

    private _decimals = 0;

    public get decimals(): number {
        return this._decimals;
    }

    public set decimals(decimals: number) {
        this._decimals = decimals;
        if (!this.checkboxControl) {
            return;
        }
        this.updateCheckboxState();
    }

    public get tokenAmount(): BigNumber {
        return new BigNumber(this.inputControl.value);
    }

    public get tokenAmountDecimals(): number {
        return this.decimalInput ? this._decimals : 0;
    }

    private get decimalInput(): boolean {
        const control = this.checkboxControl;
        if (!control) {
            return false;
        }
        return control.value;
    }

    public resetAmount() {
        this.inputControl.setValue('0');
    }

    public step(): string {
        if (this.decimalInput) {
            return this.minimumAmount().toString();
        } else {
            return '1';
        }
    }

    minimumAmount(): string {
        return (1 / (10 ** this._decimals)).toFixed(this._decimals);
    }

    public precise(value) {
        if (value.type !== 'input') {
            return;
        }

        const tokens = value.target.value;

        if (this.decimalInput && !value.inputType) {
            this.inputControl.setValue(this.getTokenAmount(tokens));
        }

        if (!this.decimalInput && value.inputType) {
            this.inputControl.setValue(new BigNumber(tokens).toFixed(0));
        }
    }

    onCheckChange(event: MatCheckboxChange) {
        const currentAmount = parseFloat(this.inputControl.value);
        let amount: string;

        if (event.checked) {
            let fixedPoints: number;
            const number = amountToDecimal(currentAmount, this._decimals);
            const decimalPart = this.getDecimalPart(number);

            if (decimalPart === 0 || currentAmount === 0) {
                fixedPoints = 0;
            } else {
                fixedPoints = this._decimals;
            }

            amount = number.toFixed(fixedPoints);
        } else {
            amount = amountFromDecimal(currentAmount, this._decimals).toString();
        }

        this.inputControl.setValue(amount);
        this.inputControl.markAsTouched();
    }

    registerOnChange(fn: any): void {
        this.inputControl.valueChanges.subscribe(fn);
    }

    registerOnTouched(fn: any): void {
        this.inputControl.registerOnChange(fn);
    }

    registerOnValidatorChange(fn: () => void): void {
    }

    setDisabledState(isDisabled: boolean): void {
        if (isDisabled) {
            this.inputControl.disable();
        } else {
            this.inputControl.enable();
        }
    }

    validate(c: AbstractControl): ValidationErrors | null {
        if (!this.inputControl.value) {
            return {empty: true};
        }
        return this.inputControl.errors;
    }

    writeValue(obj: any): void {
        if (!obj) {
            return;
        }
        this.inputControl.setValue(obj, {emitEvent: false});
    }

    private getDecimalPart(currentAmount) {
        const rounded = Math.floor(currentAmount);
        return currentAmount % rounded;
    }

    private amountValidator(tokenAmountDecimals: () => number): ValidatorFn {
        return (control: AbstractControl) => {
            const controlValue = control.value;
            const decimalPlaces = new BigNumber(controlValue).decimalPlaces();

            if (decimalPlaces > tokenAmountDecimals()) {
                return {
                    tooManyDecimals: true
                };
            } else if (controlValue === 0) {
                return {
                    invalidAmount: true
                };
            }
            return undefined;
        };
    }

    private updateCheckboxState() {
        if (this._decimals === 0) {
            this.checkboxControl.disable();
        } else {
            this.checkboxControl.enable();
        }
    }

    private getTokenAmount(tokens: string): string {
        const tokenNumber = new BigNumber(tokens);

        if (this.decimalPartIsZero(tokenNumber)) {
            return tokenNumber.toString();
        }

        if (tokenNumber.decimalPlaces() > 4) {
            return tokenNumber.toFixed(this._decimals);
        } else {
            return tokens;
        }
    }

    // noinspection JSMethodCanBeStatic
    private decimalPartIsZero(tokenNumber) {
        const noDecimals = tokenNumber.integerValue(BigNumber.ROUND_FLOOR);
        const decimalPart = tokenNumber.modulo(noDecimals);
        return decimalPart.isEqualTo(0);
    }
}
