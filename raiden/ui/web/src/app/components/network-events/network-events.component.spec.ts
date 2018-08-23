import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { CdkDetailRowDirective } from '../../directives/cdk-detail-row.directive';
import { MaterialComponentsModule } from '../../modules/material-components/material-components.module';
import { EllipsisPipe } from '../../pipes/ellipsis.pipe';
import { KeysPipe } from '../../pipes/keys.pipe';
import { SubsetPipe } from '../../pipes/subset.pipe';
import { RaidenConfig } from '../../services/raiden.config';
import { SharedService } from '../../services/shared.service';
import { MockConfig } from '../channel-table/channel-table.component.spec';
import { EventListComponent } from '../event-list/event-list.component';

import { NetworkEventsComponent } from './network-events.component';

describe('NetworkEventsComponent', () => {
    let component: NetworkEventsComponent;
    let fixture: ComponentFixture<NetworkEventsComponent>;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            declarations: [
                NetworkEventsComponent,
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
                SharedService
            ],
            imports: [
                MaterialComponentsModule,
                HttpClientTestingModule,
                NoopAnimationsModule
            ]
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(NetworkEventsComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });
});
