import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { NetworkEventsComponent } from './network-events.component';

describe('NetworkEventsComponent', () => {
  let component: NetworkEventsComponent;
  let fixture: ComponentFixture<NetworkEventsComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ NetworkEventsComponent ]
    })
    .compileComponents();
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
