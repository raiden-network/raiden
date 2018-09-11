import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { TokenPipe } from '../../pipes/token.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { SharedService } from '../../services/shared.service';
import { AddressInputComponent } from '../address-input/address-input.component';
import { MockConfig } from '../channel-table/channel-table.component.spec';
import { TokenInputComponent } from '../token-input/token-input.component';
import { TokenNetworkSelectorComponent } from '../token-network-selector/token-network-selector.component';

import { OpenDialogComponent } from './open-dialog.component';

describe('OpenDialogComponent', () => {
    let component: OpenDialogComponent;
    let fixture: ComponentFixture<OpenDialogComponent>;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                OpenDialogComponent,
                TokenInputComponent,
                AddressInputComponent,
                TokenPipe,
                TokenNetworkSelectorComponent
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
                ReactiveFormsModule,
                HttpClientTestingModule,
                NoopAnimationsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(OpenDialogComponent);
        component = fixture.componentInstance;
        fixture.detectChanges(false);
    });

    it('should be created', () => {
        expect(component).toBeTruthy();
    });
});
