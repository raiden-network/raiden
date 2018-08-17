import { HttpClientModule } from '@angular/common/http';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { fakeAsync, flush, inject, TestBed, tick } from '@angular/core/testing';
import { from, of } from 'rxjs';
import { MockConfig } from '../components/channel-table/channel-table.component.spec';
import { Channel } from '../models/channel';
import { UserToken } from '../models/usertoken';

import { ChannelPollingService } from './channel-polling.service';
import { RaidenConfig } from './raiden.config';
import { RaidenService } from './raiden.service';
import { SharedService } from './shared.service';
import Spy = jasmine.Spy;

describe('ChannelPollingService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [
                HttpClientModule,
                HttpClientTestingModule
            ],
            providers: [
                ChannelPollingService,
                SharedService,
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                RaidenService
            ]
        });
    });

    let sharedService: SharedService;
    let pollingService: ChannelPollingService;
    let pollingServiceSpy: Spy;

    const token: UserToken = {
        address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        symbol: 'TST',
        name: 'Test Suite Token',
        balance: 20
    };

    const channel1: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 10,
        settle_timeout: 500,
        userToken: token
    };

    const channel1Updated: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 20,
        settle_timeout: 500,
        userToken: token
    };

    const channel1UpdatedNegative: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 5,
        settle_timeout: 500,
        userToken: token
    };

    const channel2: Channel = {
        state: 'opened',
        channel_identifier: 2,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0xFC57d325f23b9121a8488fFdE2E6b3ef1208a20b',
        reveal_timeout: 600,
        balance: 0,
        settle_timeout: 500,
        userToken: token
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            providers: [
                ChannelPollingService,
                SharedService,
            ]
        });

        pollingService = TestBed.get(ChannelPollingService);
        sharedService = TestBed.get(SharedService);

        pollingServiceSpy = spyOn(pollingService, 'channels');
        spyOn(sharedService, 'info').and.callFake(() => {
        });
    });

    it('should be created', inject([ChannelPollingService], (service: ChannelPollingService) => {
        expect(service).toBeTruthy();
    }));

    it('should show a notification on balance increases', fakeAsync(() => {
        pollingServiceSpy.and.returnValues(from([[channel1], [channel1Updated]]));
        pollingService.startMonitoring();
        tick(5000);
        tick(5000);
        tick(5000);

        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('Balance Update');
        flush();
        pollingService.stopMonitoring();
    }));

    it('should not show a notification on when balance is reduced', fakeAsync(() => {
        pollingServiceSpy.and.returnValues(from([[channel1], [channel1UpdatedNegative]]));
        pollingService.startMonitoring();
        tick(5000);
        tick(5000);
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
        pollingService.stopMonitoring();
    }));

    it('should not send notification about channel the first time loading the channels', fakeAsync(() => {
        pollingServiceSpy.and.returnValues(from([[], [channel1]]));
        pollingService.startMonitoring();
        tick(5000);
        tick(5000);
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
        pollingService.stopMonitoring();
    }));

    it('should show notification if new channels are detected', fakeAsync(() => {
        pollingServiceSpy.and.returnValues(from([[channel1], [channel1, channel2]]));
        pollingService.startMonitoring();
        tick(5000);
        tick(5000);
        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('New channel');
        flush();
        pollingService.stopMonitoring();
    }));

    it('should not show a notification if no new channels are detected', fakeAsync(() => {
        pollingServiceSpy.and.returnValues(from([[channel1], [channel1]]));
        pollingService.startMonitoring();
        tick(5000);
        tick(5000);
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
        pollingService.stopMonitoring();
    }));
});
