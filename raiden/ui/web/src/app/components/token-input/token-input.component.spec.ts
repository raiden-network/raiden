import { async, ComponentFixture, fakeAsync, TestBed, tick } from '@angular/core/testing';
import { FormControl, FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { AllowedDecimalsDirective } from '../../directives/allowed-decimals.directive';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';

import { TokenInputComponent } from './token-input.component';

describe('TokenInputComponent', () => {
    let component: TokenInputComponent;
    let fixture: ComponentFixture<TokenInputComponent>;

    let input: HTMLInputElement;
    let checkbox: HTMLInputElement;

    let decimals: FormControl;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                TokenInputComponent,
                AllowedDecimalsDirective
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
        decimals = new FormControl(true);

        fixture = TestBed.createComponent(TokenInputComponent);
        component = fixture.componentInstance;
        component.parent = new FormGroup({
            amount: new FormControl(0),
            decimals: decimals
        });

        component.placeholder = 'Amount';
        component.errorPlaceholder = 'amount';
        fixture.detectChanges(false);
        component.ngOnInit();

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
        decimals.setValue(false);

        fixture.detectChanges();
        fixture.whenStable().then(() => {
            expect(component.step()).toBe('1');
        });
    }));

    it('should have allow an integer amount if checkbox not selected', async(() => {
        component.decimals = 18;

        decimals.setValue(false);

        input.value = '10';
        input.dispatchEvent(new Event('input'));

        fixture.detectChanges();
        fixture.whenStable().then(() => {
            expect(component.tokenAmount.isEqualTo(10)).toBe(true);
            expect(component.tokenAmountDecimals).toBe(0);
        });
    }));


    it('should allow a decimal amount if checkbox is selected', async(() => {
        component.decimals = 18;
        checkbox.click();

        input.value = '0.000000000000000010';
        input.dispatchEvent(new Event('input'));

        fixture.detectChanges();
        fixture.whenStable().then(() => {
            expect(input.value).toBe('0.000000000000000010');
            expect(component.tokenAmount.isEqualTo(1e-17)).toBe(true);
            expect(component.tokenAmountDecimals).toBe(18);
        });
    }));

    it('should show error when input value is 0', async(() => {
        component.decimals = 18;
        checkbox.click();

        input.value = '0';
        input.dispatchEvent(new Event('input'));

        fixture.detectChanges();
        fixture.whenStable().then(() => {
            expect(component.tokenAmount.isEqualTo(0)).toBe(true);
            expect(component.tokenAmountDecimals).toBe(18);
            expect(component.hasError('invalidAmount')).toBe(true);
        });
    }));

    it('should automatically change the value integer value on checkbox change', fakeAsync(() => {
        component.decimals = 8;
        checkbox.click();

        fixture.detectChanges();

        input.value = '0.00000001';

        const event = new Event('input');
        Object.assign(event, {inputType: 'mock'});
        input.dispatchEvent(event);

        checkbox.click();

        fixture.detectChanges();
        tick(100);
        fixture.whenStable().then(() => {
            expect(component.tokenAmount.isEqualTo(1)).toBe(true);
            expect(component.tokenAmountDecimals).toBe(0);
            expect(input.value).toBe('1');
        });
    }));

    it('should automatically change to the decimal value on checkbox change', fakeAsync(() => {
        decimals.setValue(false);
        component.decimals = 8;
        fixture.detectChanges();

        input.value = '1';

        const event = new Event('input');
        Object.assign(event, {inputType: 'mock'});
        input.dispatchEvent(event);

        checkbox.click();

        fixture.detectChanges();
        tick(100);
        fixture.whenStable().then(() => {
            expect(component.tokenAmount.isEqualTo(0.00000001)).toBe(true);
            expect(component.tokenAmountDecimals).toBe(8);
        });
    }));
});
