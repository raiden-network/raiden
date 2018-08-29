import { Component, Input, OnInit } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';
import { MatCheckboxChange } from '@angular/material';
import { BigNumber } from 'bignumber.js';
import { amountFromDecimal, amountToDecimal } from '../../utils/amount.converter';


@Component({
    selector: 'app-token-input',
    templateUrl: './token-input.component.html',
    styleUrls: ['./token-input.component.css'],
})
export class TokenInputComponent implements OnInit {

    @Input() placeholder: string;
    @Input() errorPlaceholder: string;
    @Input() parent: FormGroup;

    private inputControl: FormControl;
    private checkboxControl: FormControl;

    constructor() {
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
        return this.checkboxControl.value;
    }

    public resetAmount() {
        this.inputControl.setValue('0');
    }

    ngOnInit() {
        this.inputControl = this.parent.get('amount') as FormControl;
        this.checkboxControl = this.parent.get('decimals') as FormControl;
        this.updateCheckboxState();
    }

    public hasError(errorType: string): boolean {
        const control = this.inputControl;
        return control.invalid && control.hasError(errorType) && (control.dirty || control.touched);
    }

    public step(): string {
        if (this.decimalInput) {
            return (1 / (10 ** this._decimals)).toFixed(this._decimals).toString();
        } else {
            return '1';
        }
    }

    public precise(value) {
        if (this.decimalInput && value.type === 'input' && !value.placeholder) {
            const tokens = value.target.value;
            this.inputControl.setValue(this.getTokenAmount(tokens));
        }
    }

    onCheckChange(event: MatCheckboxChange) {
        const currentAmount = this.inputControl.value as number;
        let amount: string;

        if (event.checked) {
            amount = amountToDecimal(currentAmount, this._decimals).toFixed(this._decimals);
        } else {
            amount = amountFromDecimal(currentAmount, this._decimals).toString();
        }

        setTimeout(() => {
            this.inputControl.setValue(amount);
        }, 100);
    }

    private updateCheckboxState() {
        if (this._decimals === 0) {
            this.checkboxControl.disable();
        } else {
            this.checkboxControl.enable();
        }
    }

    private getTokenAmount(tokens): string {
        return new BigNumber(tokens).toFixed(this._decimals);
    }
}
