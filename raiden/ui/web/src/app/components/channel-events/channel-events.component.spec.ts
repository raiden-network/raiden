import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ChannelEventsComponent } from './channel-events.component';

describe('ChannelEventsComponent', () => {
  let component: ChannelEventsComponent;
  let fixture: ComponentFixture<ChannelEventsComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ChannelEventsComponent ]
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
