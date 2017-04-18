import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TokenNetworkComponent } from './token-network.component';

describe('TokenNetworkComponent', () => {
  let component: TokenNetworkComponent;
  let fixture: ComponentFixture<TokenNetworkComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ TokenNetworkComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(TokenNetworkComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
