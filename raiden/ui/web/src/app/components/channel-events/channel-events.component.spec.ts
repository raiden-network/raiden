import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { ActivatedRoute } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';
import { of } from 'rxjs';
import { CdkDetailRowDirective } from '../../directives/cdk-detail-row.directive';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { EllipsisPipe } from '../../pipes/ellipsis.pipe';
import { KeysPipe } from '../../pipes/keys.pipe';
import { SubsetPipe } from '../../pipes/subset.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';
import { EventListComponent } from '../event-list/event-list.component';

import { ChannelEventsComponent } from './channel-events.component';

describe('ChannelEventsComponent', () => {
    let component: ChannelEventsComponent;
    let fixture: ComponentFixture<ChannelEventsComponent>;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                ChannelEventsComponent,
                EventListComponent,
                CdkDetailRowDirective,
                KeysPipe,
                EllipsisPipe,
                SubsetPipe
            ],
            providers: [
                {
                    provide: RaidenConfig,
                    useClass: MockConfig
                },
                {
                    provide: ActivatedRoute,
                    useValue: {
                        paramMap: of({channel_identifier: 123}),
                        queryParamMap: of({
                            token_address: '0x',
                            partner_address: '0x'
                        })
                    }
                },
                SharedService
            ],
            imports: [
                MaterialComponentsModule,
                HttpClientTestingModule,
                NoopAnimationsModule
            ]
        })
            .compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(ChannelEventsComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });
});
