import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { RaidenConfig } from '../../services/raiden.config';
import { SharedService } from '../../services/shared.service';
import { AddressInputComponent } from '../address-input/address-input.component';
import { MockConfig } from '../channel-table/channel-table.component.spec';

import { RegisterDialogComponent } from './register-dialog.component';

describe('RegisterDialogComponent', () => {
    let component: RegisterDialogComponent;
    let fixture: ComponentFixture<RegisterDialogComponent>;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                RegisterDialogComponent,
                AddressInputComponent
            ],
            providers: [
                {
                    provide: MAT_DIALOG_DATA,
                    useValue: {}
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
        fixture = TestBed.createComponent(RegisterDialogComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should be created', () => {
        expect(component).toBeTruthy();
    });
});
