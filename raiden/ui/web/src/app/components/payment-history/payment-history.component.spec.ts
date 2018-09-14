import { HttpClientTestingModule } from '@angular/common/http/testing';
import { DebugElement } from '@angular/core';
import { async, ComponentFixture, fakeAsync, flush, TestBed, tick } from '@angular/core/testing';
import { MatCard } from '@angular/material';
import { By } from '@angular/platform-browser';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';
import { BehaviorSubject, of } from 'rxjs';
import { PaymentEvent } from '../../models/payment-event';
import { UserToken } from '../../models/usertoken';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { DecimalPipe } from '../../pipes/decimal.pipe';
import { TokenPipe } from '../../pipes/token.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';

import { PaymentHistoryComponent } from './payment-history.component';

describe('PaymentHistoryComponent', () => {
    let component: PaymentHistoryComponent;
    let fixture: ComponentFixture<PaymentHistoryComponent>;
    let spy: jasmine.Spy;

    let dataProvider: BehaviorSubject<PaymentEvent[]>;

    const connectedToken: UserToken = {
        address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
        symbol: 'TST',
        name: 'Test Suite Token',
        decimals: 8,
        balance: 20,
        connected: {
            channels: 5,
            funds: 10,
            sum_deposits: 50
        }
    };

    const mockData: PaymentEvent[] = [
        {
            'event': 'EventPaymentSendFailed',
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'reason': 'insufficient funds',
            'identifier': 1536847754083
        },
        {
            'event': 'EventPaymentReceivedSuccess',
            'amount': 5,
            'initiator': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847755083
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 35,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847756083
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 20,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847757083
        },
        {
            'event': 'EventPaymentReceivedSuccess',
            'amount': 5,
            'initiator': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847758103
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 11,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847759000
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 1,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847760030
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 4,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847760130
        },
        {
            'event': 'EventPaymentReceivedSuccess',
            'amount': 8,
            'initiator': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847760230
        },
        {
            'event': 'EventPaymentSentSuccess',
            'amount': 2,
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847760330
        },
        {
            'event': 'EventPaymentReceivedSuccess',
            'amount': 5,
            'initiator': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'identifier': 1536847760430
        },
        {
            'event': 'EventPaymentSendFailed',
            'target': '0x82641569b2062B545431cF6D7F0A418582865ba7',
            'reason': 'insufficient funds',
            'identifier': 1536847760442
        }
    ];

    function getVisibleEventCards(): DebugElement[] {
        const historyList = fixture.debugElement.query(By.css('#payment-history'));
        return historyList.queryAll(By.directive(MatCard));
    }

    const tokenNetwork = '0x0f114A1E9Db192502E7856309cc899952b3db1ED';
    const partnerAddress = '0xc52952Ebad56f2c5E5b42bb881481Ae27D036475';

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                PaymentHistoryComponent,
                DecimalPipe,
                TokenPipe
            ],
            providers: [
                SharedService,
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                {
                    provide: ActivatedRoute,
                    useValue: {
                        queryParamMap: new BehaviorSubject(convertToParamMap({
                            token_address: tokenNetwork,
                            partner_address: partnerAddress
                        }))
                    }
                },
                RaidenService
            ],
            imports: [
                MaterialComponentsModule,
                RouterTestingModule,
                HttpClientTestingModule,
                NoopAnimationsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        dataProvider = new BehaviorSubject([]);
        const raidenService = TestBed.get(RaidenService);
        spy = spyOn(raidenService, 'getPaymentHistory');
        spy.and.returnValue(dataProvider);

        const tokenSpy = spyOn(raidenService, 'getUserToken');
        tokenSpy.and.returnValue(of(connectedToken));
        fixture = TestBed.createComponent(PaymentHistoryComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', fakeAsync(() => {
        tick();
        expect(component).toBeTruthy();
        flush();
    }));

    function noPaymentElement() {
        const elements = fixture.debugElement.queryAll(By.css('h2'));
        const label = 'No payments found!';
        return elements.filter(value => (value.nativeElement as HTMLHeadingElement).textContent === label);
    }

    it('should display a no payments found message if there is no response', fakeAsync(() => {
        tick();
        fixture.detectChanges();
        expect(noPaymentElement().length).toBe(1);
        flush();
    }));

    it('should display the first page of payments when opening', fakeAsync(() => {
        dataProvider.next(mockData);
        tick();

        fixture.detectChanges();
        expect(noPaymentElement().length).toBe(0, 'Should not show the no payment message');

        const cards = getVisibleEventCards();
        expect(cards.length).toBe(component.pageSize, 'Should display a full page');

        const id: string = cards[0].properties['id'];
        expect(id).toBe('payment-event-1536847760442');
        component.ngOnDestroy();
        flush();
    }));

    it('should change page when user clicks next', fakeAsync(() => {
        dataProvider.next(mockData);
        tick();

        fixture.detectChanges();
        const nextButton = fixture.debugElement.query(By.css('.mat-paginator-navigation-next'));
        const button = nextButton.nativeElement as HTMLElement;
        button.click();
        tick();
        fixture.detectChanges();

        const cards = getVisibleEventCards();
        expect(cards.length).toBe(2);

        const id: string = cards[0].properties['id'];
        expect(id).toBe(`payment-event-${mockData[1].identifier}`);

        component.ngOnDestroy();
        flush();
    }));
});
