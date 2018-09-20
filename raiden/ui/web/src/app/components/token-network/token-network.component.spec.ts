import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterTestingModule } from '@angular/router/testing';
import { ClipboardModule } from 'ngx-clipboard';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { DecimalPipe } from '../../pipes/decimal.pipe';
import { NetworkType } from '../../services/network-type.enum';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';

import { TokenNetworkComponent } from './token-network.component';

describe('TokenNetworkComponent', () => {
    let component: TokenNetworkComponent;
    let fixture: ComponentFixture<TokenNetworkComponent>;
    let mockConfiguration: MockConfig;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                TokenNetworkComponent,
                DecimalPipe
            ],
            providers: [
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                RaidenService,
                SharedService
            ],
            imports: [
                MaterialComponentsModule,
                RouterTestingModule,
                FormsModule,
                ClipboardModule,
                NoopAnimationsModule,
                HttpClientTestingModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        mockConfiguration = TestBed.get(RaidenConfig);
        fixture = TestBed.createComponent(TokenNetworkComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('should have a registration button when configuration is testnet', async(() => {
        mockConfiguration.config.network_type = NetworkType.TEST;
        fixture.detectChanges();
        const element = fixture.debugElement.query(By.css('#token-registration'));
        expect(element).toBeTruthy();
    }));

    it('should have registration disabled when configuration is mainnet', async(() => {
        mockConfiguration.config.network_type = NetworkType.MAIN;
        fixture.detectChanges();
        const element = fixture.debugElement.query(By.css('#token-registration'));
        expect(element).toBeFalsy();
    }));
});
