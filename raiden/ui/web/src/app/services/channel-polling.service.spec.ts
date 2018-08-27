import { HttpClientModule } from '@angular/common/http';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { fakeAsync, flush, inject, TestBed } from '@angular/core/testing';
import { from } from 'rxjs';
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

    let pollingService: ChannelPollingService;
    let sharedService: SharedService;
    let raidenService: RaidenService;
    let raidenServiceSpy: Spy;

    const token: UserToken = {
        address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        symbol: 'TST',
        name: 'Test Suite Token',
        balance: 20,
        decimals: 8
    };

    const token2: UserToken = {
        address: '0xeB7f4BBAa1714F3E5a12fF8B681908D7b98BD195',
        symbol: 'TST2',
        name: 'Test Suite Token 2',
        balance: 20,
        decimals: 8
    };


    const channel1: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 10,
        total_deposit: 10,
        settle_timeout: 500,
        userToken: token
    };

    const channel1Network2: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0xeB7f4BBAa1714F3E5a12fF8B681908D7b98BD195',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 20,
        total_deposit: 10,
        settle_timeout: 500,
        userToken: token2
    };

    const channel1Updated: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 20,
        total_deposit: 10,
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
        total_deposit: 10,
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
        total_deposit: 10,
        settle_timeout: 500,
        userToken: token
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            providers: [
                ChannelPollingService,
                RaidenService,
                SharedService,
            ]
        });

        raidenService = TestBed.get(RaidenService);
        sharedService = TestBed.get(SharedService);
        pollingService = TestBed.get(ChannelPollingService);

        raidenServiceSpy = spyOn(raidenService, 'getChannels');
        spyOn(sharedService, 'info').and.callFake(() => {
        });
    });

    it('should be created', inject([ChannelPollingService], (service: ChannelPollingService) => {
        expect(service).toBeTruthy();
    }));

    it('should show a notification on balance increases', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1], [channel1Updated]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('Balance Update');
        subscription.unsubscribe();
        flush();
    }));

    it('should not show a notification on when balance is reduced', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1], [channel1UpdatedNegative]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        subscription.unsubscribe();
        flush();
    }));

    it('should not send notification about channel the first time loading the channels', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[], [channel1]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        subscription.unsubscribe();
        flush();
    }));

    it('should show notification if new channels are detected', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1], [channel1, channel2]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('New channel');
        subscription.unsubscribe();
        flush();
    }));

    it('should not show a notification if no new channels are detected', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1], [channel1]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        subscription.unsubscribe();
        flush();
    }));

    it('should not throw if a channel is removed from the list', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1, channel2], [channel1]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        subscription.unsubscribe();
        flush();
    }));


    it('should not show a notification for the same identifier on different network', fakeAsync(() => {
        raidenServiceSpy.and.returnValues(from([[channel1, channel1Network2], [channel1Network2]]));
        const subscription = pollingService.channels().subscribe();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        subscription.unsubscribe();
        flush();
    }));
});
