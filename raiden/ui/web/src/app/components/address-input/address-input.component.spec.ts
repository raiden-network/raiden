import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { MatError, MatIcon } from '@angular/material';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';

import { AddressInputComponent } from './address-input.component';

describe('AddressInputComponent', () => {
    let component: AddressInputComponent;
    let fixture: ComponentFixture<AddressInputComponent>;

    const nonEip55Address = '0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359';
    const errorPlaceholder = 'Token network';

    let input: HTMLInputElement;
    let mockConfig: MockConfig;

    function errorMessage() {
        const debugElement = fixture.debugElement.query(By.directive(MatError));
        const element = debugElement.query(By.css('span'));
        const span = element.nativeElement as HTMLSpanElement;
        return span.innerText;
    }

    function mockInput(inputValue: string) {
        input.value = inputValue;
        component.addressFc.markAsTouched();
        input.dispatchEvent(new Event('input'));
    }

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                AddressInputComponent
            ],
            providers: [
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                SharedService
            ],
            imports: [
                MaterialComponentsModule,
                ReactiveFormsModule,
                HttpClientTestingModule,
                NoopAnimationsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        mockConfig = TestBed.get(RaidenConfig);
        fixture = TestBed.createComponent(AddressInputComponent);
        component = fixture.componentInstance;
        component.placeholder = 'Token Address';
        component.errorPlaceholder = 'Token network';

        fixture.detectChanges();

        const inputDebugElement = fixture.debugElement.query(By.css('input[type=text]'));
        input = inputDebugElement.nativeElement as HTMLInputElement;
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('should not display identicon container if displayIdenticon is false', () => {
        component.displayIdenticon = false;

        fixture.detectChanges();
        const identiconElement = fixture.debugElement.query(By.css('.identicon'));
        expect(identiconElement).toBeFalsy();
    });

    it('should display identicon container if displayIdenticon is true', () => {
        component.displayIdenticon = true;
        fixture.detectChanges();
        const identiconPlaceholder = fixture.debugElement.query(By.directive(MatIcon));
        expect(identiconPlaceholder).toBeTruthy();
    });

    it('should show error when address is not in checksum format', () => {
        component.displayIdenticon = true;
        mockConfig.web3.checksumAddress = '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359';
        fixture.detectChanges();

        mockInput(nonEip55Address);
        fixture.detectChanges();
        expect(errorMessage()).toBe('Address is not in checksum format: 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
    });

    it('should show an error if the input is empty', () => {
        mockInput('');
        fixture.detectChanges();
        expect(errorMessage()).toBe(`${component.errorPlaceholder} address cannot be empty`);
    });

    it('should show an error if the error is not 42 characters long', () => {
        mockInput('0x');
        fixture.detectChanges();
        expect(errorMessage()).toBe(`Invalid ${component.errorPlaceholder} address length`);
    });

    it('should show an error if the address is not valid', () => {
        mockInput('abbfosdaiudaisduaosiduaoisduaoisdu23423423');
        fixture.detectChanges();
        expect(errorMessage()).toBe(`The ${component.errorPlaceholder} address is not in a valid format`);
    });

    it('should show an error if the address is own address', () => {
        mockConfig.web3.isChecksum = true;
        const service = TestBed.get(RaidenService);
        const address = '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359';
        spyOnProperty(service, 'raidenAddress', 'get').and.returnValue(address);
        mockInput(address);
        fixture.detectChanges();
        expect(errorMessage()).toBe(`You cannot use your own address for this action`);
    });

    it('should update formcontrol value properly if a truthy value is passed', () => {
        const address = '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359';
        component.writeValue(address);
        expect(component.addressFc.value).toBe(address);
    });

    it('should not update form control when a falsy value is passed', () => {
        const address = '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359';
        component.writeValue(address);
        component.writeValue(null);
        expect(component.addressFc.value).toBe(address);
    });
});
