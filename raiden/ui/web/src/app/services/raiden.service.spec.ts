import { HttpClientModule } from '@angular/common/http';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { inject, TestBed } from '@angular/core/testing';
import { MockConfig } from '../components/channel-table/channel-table.component.spec';
import { RaidenConfig } from './raiden.config';

import { RaidenService } from './raiden.service';
import { SharedService } from './shared.service';

describe('RaidenService', () => {

    const tokenAddress = '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8';

    let mockHttp: HttpTestingController;
    let sharedService: SharedService;
    let endpoint: String;

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
        spyOn(sharedService, 'msg');
    });

    afterEach(inject([HttpTestingController], (backend: HttpTestingController) => {
        backend.verify();
    }));

    it('When token creation fails there should be a nice message', inject([RaidenService], (service: RaidenService) => {

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

        expect(sharedService.msg).toHaveBeenCalledTimes(1);

        // @ts-ignore
        const payload = sharedService.msg.calls.first().args[0];

        expect(payload.severity).toBe('error', 'Severity should be error');
        expect(payload.summary).toBe('Raiden Error', 'It should be a Raiden Error');
        expect(payload.detail).toBe(errorMessage);
    }));

    it('Show a proper response when non-EIP addresses are passed in channel creation', inject([RaidenService], (service: RaidenService) => {
        const partnerAddress = '0xc52952ebad56f2c5e5b42bb881481ae27d036475';

        service.openChannel(tokenAddress, partnerAddress, 600, 10).subscribe(() => {
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

        expect(sharedService.msg).toHaveBeenCalledTimes(1);

        // @ts-ignore
        const payload = sharedService.msg.calls.first().args[0];

        expect(payload.severity).toBe('error', 'Severity should be error');
        expect(payload.summary).toBe('Raiden Error', 'It should be a Raiden Error');
        expect(payload.detail).toBe('partner_address: Not a valid EIP55 encoded address');

    }));
});
