import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TokenEventsComponent } from './token-events.component';

describe('TokenEventsComponent', () => {
  let component: TokenEventsComponent;
  let fixture: ComponentFixture<TokenEventsComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ TokenEventsComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(TokenEventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
