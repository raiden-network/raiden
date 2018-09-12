import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';

import { TokenInputComponent } from './token-input.component';

describe('TokenInputComponent', () => {
    let component: TokenInputComponent;
    let fixture: ComponentFixture<TokenInputComponent>;

    let input: HTMLInputElement;
    let checkbox: HTMLInputElement;

    function mockInput(inputValue: string, isStep: boolean = false) {
        input.value = inputValue;
        const event = new Event('input');
        if (!isStep) {
            Object.assign(event, {inputType: 'mock'});
        }

        input.dispatchEvent(event);
        component.form.get('amount').markAsTouched();
    }


    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                TokenInputComponent
            ],
            imports: [
                MaterialComponentsModule,
                NoopAnimationsModule,
                FormsModule,
                ReactiveFormsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(TokenInputComponent);
        component = fixture.componentInstance;
        component.placeholder = 'Amount';
        component.errorPlaceholder = 'amount';
        fixture.detectChanges();

        const inputDebugElement = fixture.debugElement.query(By.css('input[type=number]'));
        input = inputDebugElement.nativeElement as HTMLInputElement;

        const checkboxElement = fixture.debugElement.query(By.css('input[type=checkbox]'));
        checkbox = checkboxElement.nativeElement as HTMLInputElement;
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('should have decimal input active by default', () => {
        expect(checkbox.checked).toBe(true);
    });

    it('should default to 0 amount', () => {
        expect(input.value).toBe('0');
    });

    it('should have decimal step when checkbox is not selected', () => {
        component.decimals = 18;
        expect(component.step()).toBe('0.000000000000000001');
    });

    it('should have integer step when checkbox not checked', async(() => {
        component.decimals = 18;
        component.form.get('decimals').setValue(false);
        fixture.detectChanges();

        expect(component.step()).toBe('1');
    }));

    it('should have allow an integer amount if checkbox not selected', () => {
        component.decimals = 18;
        component.form.get('decimals').setValue(false);

        mockInput('10');

        fixture.detectChanges();
        expect(component.tokenAmount.isEqualTo(10)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(0);
    });


    it('should allow a decimal amount if checkbox is selected', () => {
        component.decimals = 18;

        mockInput('0.000000000000000010');

        fixture.detectChanges();
        expect(input.value).toBe('0.000000000000000010');
        expect(component.tokenAmount.isEqualTo(1e-17)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(18);
    });

    it('should show error when input value is 0', () => {
        component.decimals = 18;

        mockInput('0');
        fixture.detectChanges();

        expect(component.tokenAmount.isEqualTo(0)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(18);
        expect(component.form.get('amount').errors['invalidAmount']).toBe(true);
    });

    it('should automatically change the value integer value on checkbox change', () => {
        component.decimals = 8;

        mockInput('0.00000001');
        checkbox.click();
        fixture.detectChanges();

        expect(component.tokenAmount.isEqualTo(1)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(0);
    });

    it('should automatically change to the decimal value on checkbox change', () => {
        component.form.get('decimals').setValue(false);
        component.decimals = 8;
        fixture.detectChanges();

        mockInput('1');

        checkbox.click();
        fixture.detectChanges();

        expect(component.tokenAmount.isEqualTo(0.00000001)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(8);
    });

    it('should automatically convert between decimal and integer', () => {
        component.form.get('decimals').setValue(false);
        component.decimals = 8;
        fixture.detectChanges();

        mockInput('1');

        checkbox.click();
        fixture.detectChanges();

        expect(component.tokenAmount.isEqualTo(0.00000001)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(8);

        checkbox.click();
        fixture.detectChanges();

        expect(component.tokenAmount.isEqualTo(1)).toBe(true);
        expect(component.tokenAmountDecimals).toBe(0);
    });
});
