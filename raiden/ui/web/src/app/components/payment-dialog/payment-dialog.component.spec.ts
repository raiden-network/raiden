import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { AllowedDecimalsDirective } from '../../directives/allowed-decimals.directive';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { TokenPipe } from '../../pipes/token.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';
import { TokenInputComponent } from '../token-input/token-input.component';
import { PaymentDialogComponent, PaymentDialogPayload } from './payment-dialog.component';

describe('PaymentDialogComponent', () => {
    let component: PaymentDialogComponent;
    let fixture: ComponentFixture<PaymentDialogComponent>;

    beforeEach(async(() => {
        const payload: PaymentDialogPayload = {
            tokenAddress: '',
            amount: 0,
            targetAddress: '',
            decimals: 0
        };
        TestBed.configureTestingModule({
            declarations: [
                PaymentDialogComponent,
                TokenPipe,
                AllowedDecimalsDirective,
                TokenInputComponent
            ],
            providers: [
                {
                    provide: MAT_DIALOG_DATA,
                    useValue: payload
                },
                {
                    provide: MatDialogRef,
                    useValue: {}
                },
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                SharedService
            ],
            imports: [
                MaterialComponentsModule,
                NoopAnimationsModule,
                ReactiveFormsModule,
                HttpClientTestingModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(PaymentDialogComponent);
        component = fixture.componentInstance;
        fixture.detectChanges(false);
    });

    it('should be created', () => {
        expect(component).toBeTruthy();
    });
});
