import { fakeAsync, flush, inject, TestBed, tick } from '@angular/core/testing';
import { Observable, of } from 'rxjs';
import { Channel } from '../models/channel';
import { UserToken } from '../models/usertoken';

import { ChannelChecker } from './channel-checker.service';
import { ChannelPollingService } from './channel-polling.service';
import { SharedService } from './shared.service';

class MockChannelPollingService {
    public channels$: Observable<Channel[]>;

    public refreshing(): Observable<boolean> {
        return of(true);
    }

    public channels(): Observable<Channel[]> {
        return this.channels$;
    }

    public refresh() {
    }
}

describe('ChannelChecker', () => {

    let sharedService: SharedService;
    let pollingService: MockChannelPollingService;
    let channelChecker: ChannelChecker;

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
                ChannelChecker,
                SharedService,
                {
                    provide: ChannelPollingService,
                    useClass: MockChannelPollingService
                },
            ]
        });

        sharedService = TestBed.get(SharedService);
        pollingService = TestBed.get(ChannelPollingService);
        channelChecker = TestBed.get(ChannelChecker);
        spyOn(sharedService, 'info');
    });

    it('should be created', inject([ChannelChecker], (service: ChannelChecker) => {
        expect(service).toBeTruthy();
    }));

    it('should show a notification on balance increases', fakeAsync(() => {
        pollingService.channels$ = of([channel1], [channel1Updated]);
        channelChecker.startMonitoring();
        tick();
        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('Balance Update');
        flush();
    }));

    it('should not show a notification on when balance is reduced', fakeAsync(() => {
        pollingService.channels$ = of([channel1], [channel1UpdatedNegative]);
        channelChecker.startMonitoring();
        tick();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
    }));

    it('should not send notification about channel the first time loading the channels', fakeAsync(() => {
        pollingService.channels$ = of([], [channel1]);
        channelChecker.startMonitoring();
        tick();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
    }));

    it('should show notification if new channels are detected', fakeAsync(() => {
        pollingService.channels$ = of([channel1], [channel1, channel2]);
        channelChecker.startMonitoring();
        tick();
        expect(sharedService.info).toHaveBeenCalledTimes(1);
        // @ts-ignore
        const payload = sharedService.info.calls.first().args[0];
        expect(payload.title).toBe('New channel');
        flush();
    }));

    it('should not show a notification if no new channels are detected', fakeAsync(() => {
        pollingService.channels$ = of([channel1], [channel1]);
        channelChecker.startMonitoring();
        tick();
        expect(sharedService.info).toHaveBeenCalledTimes(0);
        flush();
    }));
});
