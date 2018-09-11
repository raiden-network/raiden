import { HttpClientModule } from '@angular/common/http';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { fakeAsync, flush, inject, TestBed, tick } from '@angular/core/testing';
import { BigNumber } from 'bignumber.js';
import { of } from 'rxjs';
import { MockConfig } from '../components/channel-table/channel-table.component.spec';
import { Channel } from '../models/channel';
import { UserToken } from '../models/usertoken';
import { RaidenConfig } from './raiden.config';

import { CallbackFunc, RaidenService } from './raiden.service';
import { SharedService } from './shared.service';

describe('RaidenService', () => {

    const tokenAddress = '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8';

    let mockHttp: HttpTestingController;
    let sharedService: SharedService;
    let endpoint: String;

    let service: RaidenService;

    const channel1: Channel = {
        state: 'opened',
        channel_identifier: 1,
        token_address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        partner_address: '0x774aFb0652ca2c711fD13e6E9d51620568f6Ca82',
        reveal_timeout: 600,
        balance: 10,
        total_deposit: 10,
        settle_timeout: 500,
        userToken: null
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
        userToken: null
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [
                HttpClientModule,
                HttpClientTestingModule
            ],
            providers: [
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                RaidenService,
                SharedService
            ]
        });

        mockHttp = TestBed.get(HttpTestingController);

        endpoint = TestBed.get(RaidenConfig).api;
        sharedService = TestBed.get(SharedService);
        service = TestBed.get(RaidenService);

        spyOn(sharedService, 'error');
        spyOn(service, 'raidenAddress$').and.returnValue(of('0x504300C525CbE91Adb3FE0944Fe1f56f5162C75C'));
    });

    afterEach(inject([HttpTestingController], (backend: HttpTestingController) => {
        backend.verify();
    }));

    it('When token creation fails there should be a nice message', () => {

        service.registerToken(tokenAddress).subscribe(() => {
            fail('On next should not be called');
        }, (error) => {
            expect(error).toBeTruthy('An error is expected');
        });

        const registerRequest = mockHttp.expectOne({
            url: `${endpoint}/tokens/${tokenAddress}`,
            method: 'PUT'
        });

        const errorMessage = 'Token already registered';
        const errorBody = {
            errors: errorMessage
        };

        registerRequest.flush(errorBody, {
            status: 409,
            statusText: ''
        });

        expect(sharedService.error).toHaveBeenCalledTimes(1);

        // @ts-ignore
        const payload = sharedService.error.calls.first().args[0];

        expect(payload.title).toBe('Raiden Error', 'It should be a Raiden Error');
        expect(payload.description).toBe(errorMessage);
    });

    it('Show a proper response when non-EIP addresses are passed in channel creation', () => {
        const partnerAddress = '0xc52952ebad56f2c5e5b42bb881481ae27d036475';

        service.openChannel(tokenAddress, partnerAddress, 500, 10, 8).subscribe(() => {
            fail('On next should not be called');
        }, (error) => {
            expect(error).toBeTruthy('An error was expected');
        });

        const openChannelRequest = mockHttp.expectOne({
            url: `${endpoint}/channels`,
            method: 'PUT'
        });

        const errorBody = {'errors': {'partner_address': ['Not a valid EIP55 encoded address']}};

        openChannelRequest.flush(errorBody, {
            status: 409,
            statusText: ''
        });

        expect(sharedService.error).toHaveBeenCalledTimes(1);

        // @ts-ignore
        const payload = sharedService.error.calls.first().args[0];

        expect(payload.title).toBe('Raiden Error', 'It should be a Raiden Error');
        expect(payload.description).toBe('partner_address: Not a valid EIP55 encoded address');

    });

    it('should have user token included in the channels', fakeAsync(() => {

        const token: UserToken = {
            address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            symbol: 'TST',
            name: 'Test Suite Token',
            decimals: 8,
            balance: 20
        };

        service.tokenContract = {
            at: () => ({
                name: (callback: CallbackFunc) => {
                    callback(null, token.name);
                },
                balanceOf: (address: String, callback: CallbackFunc) => {
                    callback(null, {
                        toNumber: () => token.balance
                    });
                },
                symbol: (callback: CallbackFunc) => {
                    callback(null, token.symbol);
                },
                decimals: (callback: CallbackFunc) => {
                    callback(null, new BigNumber(token.decimals));
                }
            })
        };

        service.getChannels().subscribe((channels: Array<Channel>) => {
            channels.forEach(value => {
                expect(value.userToken).toBeTruthy('UserToken should not be null');
                expect(value.userToken.address).toBe(token.address);
            });
        }, (error) => {
            fail(error);
        });

        const getChannelsRequest = mockHttp.expectOne({
            url: `${endpoint}/channels`,
            method: 'GET'
        });

        getChannelsRequest.flush([
            channel1,
            channel2
        ], {
            status: 200,
            statusText: 'All good'
        });

        tick();

        mockHttp.expectOne({
            url: `${endpoint}/address`,
            method: 'GET'
        }).flush({
            own_address: '0x504300C525CbE91Adb3FE0944Fe1f56f5162C75C'
        }, {
            status: 200,
            statusText: 'All Good'
        });
        flush();
    }));

    it('should show an error message for JSON RPC errors while fetching channels', fakeAsync(() => {

        const rpcError = Error('Invalid JSON RPC response');

        // noinspection JSUnusedLocalSymbols
        service.tokenContract = {
            at: () => ({
                name: (callback: CallbackFunc) => {
                    throw rpcError;
                },
                balanceOf: (address: String, callback: CallbackFunc) => {
                    throw rpcError;
                },
                symbol: (callback: CallbackFunc) => {
                    throw rpcError;
                }
            })
        };

        service.getChannels().subscribe(() => {
            fail('Call should fail with error');
        }, (error) => {
            expect(error).toBeTruthy();
        });

        mockHttp.expectOne({
            url: `${endpoint}/channels`,
            method: 'GET'
        }).flush([
            channel1,
            channel2
        ], {
            status: 200,
            statusText: 'All good'
        });

        mockHttp.expectOne({
            url: `${endpoint}/address`,
            method: 'GET'
        }).flush({
            own_address: '0x504300C525CbE91Adb3FE0944Fe1f56f5162C75C'
        }, {
            status: 200,
            statusText: 'All Good'
        });

        expect(sharedService.error).toHaveBeenCalledTimes(1);

        // @ts-ignore
        const payload = sharedService.error.calls.first().args[0];

        expect(payload.title).toBe('Raiden Error', 'It should be a Raiden Error');
        expect(payload.description).toContain('Could not access the JSON-RPC endpoint');

        flush();
    }));


    it('should show an error message for JSON RPC errors when fetching a token', fakeAsync(() => {
        const rpcError = Error('Invalid JSON RPC response');

        // noinspection JSUnusedLocalSymbols
        service.tokenContract = {
            at: () => ({
                name: (callback: CallbackFunc) => {
                    throw rpcError;
                },
                balanceOf: (address: String, callback: CallbackFunc) => {
                    throw rpcError;
                },
                symbol: (callback: CallbackFunc) => {
                    throw rpcError;
                }
            })
        };

        service.getUserToken(tokenAddress, false).subscribe(() => {
            fail('There should be an error');
        }, (error) => {
            expect(error).toBeTruthy();
            expect(error.message).toContain('Could not access the JSON-RPC endpoint');
        });

        tick();

        mockHttp.expectOne({
            url: `${endpoint}/address`,
            method: 'GET'
        }).flush({
            own_address: '0x504300C525CbE91Adb3FE0944Fe1f56f5162C75C'
        }, {
            status: 200,
            statusText: 'All Good'
        });

        flush();
    }));
});
