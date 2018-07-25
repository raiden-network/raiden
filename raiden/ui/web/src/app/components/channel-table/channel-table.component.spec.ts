import { HttpClient, HttpHandler } from '@angular/common/http';
import { async, ComponentFixture, fakeAsync, flush, TestBed, tick } from '@angular/core/testing';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import {
    ButtonModule,
    DataTableModule,
    DialogModule,
    DropdownModule,
    Menu,
    MenuItem,
    MenuModule,
    TabViewModule
} from 'primeng/primeng';
import { of } from 'rxjs/internal/observable/of';
import { Channel } from '../../models/channel';
import { UserToken } from '../../models/usertoken';
import { EllipsisPipe } from '../../pipes/ellipsis.pipe';
import { KeysPipe } from '../../pipes/keys.pipe';
import { SubsetPipe } from '../../pipes/subset.pipe';
import { TokenPipe } from '../../pipes/token.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { EventListComponent } from '../event-list/event-list.component';
import { OpenDialogComponent } from '../open-dialog/open-dialog.component';

import { ChannelTableComponent } from './channel-table.component';
import Spy = jasmine.Spy;

export class MockConfig extends RaidenConfig {
    public web3: any = {
        eth: {
            latestBlock: 3694423,
            contract: () => {
            }
        }
    };
}

describe('ChannelTableComponent', () => {
    let component: ChannelTableComponent;
    let fixture: ComponentFixture<ChannelTableComponent>;
    let raidenServiceSpy: Spy;
    let tokenSpy: Spy;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                ChannelTableComponent,
                EventListComponent,
                OpenDialogComponent,
                TokenPipe,
                EllipsisPipe,
                KeysPipe,
                SubsetPipe
            ],
            providers: [
                SharedService,
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                RaidenService,
                HttpClient,
                HttpHandler
            ],
            imports: [
                DataTableModule,
                TabViewModule,
                MenuModule,
                FormsModule,
                ReactiveFormsModule,
                DialogModule,
                FormsModule,
                ButtonModule,
                DropdownModule,
                NoopAnimationsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(ChannelTableComponent);
        const service: RaidenService = TestBed.get(RaidenService);
        raidenServiceSpy = spyOn(service, 'getChannels');
        tokenSpy = spyOn(service, 'getUserToken');
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('should update action when channel has balance', fakeAsync(() => {

        const channel1: Channel = {
            state: 'opened',
            channel_identifier: '0xc0ecf413bfc8fc6b0e313b5ae231084e1c397b96ed5c0ec3d5ee3b5558ab20be',
            token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
            reveal_timeout: 600,
            balance: 10,
            settle_timeout: 500
        };

        const channel2: Channel = {
            state: 'opened',
            channel_identifier: '0xcf4f8999d22fd1a783fc6236b1ba1599cdc26ebedb36e053b973fc56a3280d0e',
            token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            partner_address: '0xFC57d325f23b9121a8488fFdE2E6b3ef1208a20b',
            reveal_timeout: 600,
            balance: 0,
            settle_timeout: 500
        };

        const channel2Balance: Channel = {
            state: 'opened',
            channel_identifier: '0xcf4f8999d22fd1a783fc6236b1ba1599cdc26ebedb36e053b973fc56a3280d0e',
            token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            partner_address: '0xFC57d325f23b9121a8488fFdE2E6b3ef1208a20b',
            reveal_timeout: 600,
            balance: 10,
            settle_timeout: 500
        };

        const channel3: Channel = {
            state: 'opened',
            channel_identifier: '0x82852927dd7fb86339af0c57566b0068e3341615a759950ea7de9a64f63f7d2a',
            token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            partner_address: '0xfB398E621c15E2BC5Ae6A508D8D89AF1f88c93e8',
            reveal_timeout: 600,
            balance: 10,
            settle_timeout: 500
        };

        const channel4: Channel = {
            state: 'closed',
            channel_identifier: '0xa152038763d73b05df7b036f477236b527ad14a249e4077fb4048d845226ac43',
            token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            partner_address: '0x8A0cE8bDA200D64d858957080bf7eDDD3371135F',
            reveal_timeout: 600,
            balance: 60,
            settle_timeout: 600

        };

        const token: UserToken = {
            address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            symbol: 'TST',
            name: 'Test Suite Token',
            balance: 20
        };

        raidenServiceSpy
            .and
            .returnValues(
                of([channel1, channel2, channel3, channel4]),
                of([channel1, channel2Balance, channel3, channel4])
            );

        tokenSpy.and.returnValue(of(token));

        component.ngOnInit();
        tick(5000);
        fixture.detectChanges();

        let menus = fixture.debugElement.queryAll(By.css('.ui-menu'));
        let menu: Menu = menus[1].componentInstance;
        let menuItem: MenuItem = menu.model[0];

        expect(menuItem.disabled).toBe(true, 'Transfer should be disabled with 0 balance');

        tick(5000);
        fixture.detectChanges();

        menus = fixture.debugElement.queryAll(By.css('.ui-menu'));
        menu = menus[1].componentInstance;
        menuItem = menu.model[0];

        expect(menuItem.disabled).toBe(false, 'Transfer option should be enabled with positive balance');

        component.ngOnDestroy();
        flush();
    }));
});
