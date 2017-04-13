import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UserinteractionComponent } from './userinteraction.component';

describe('UserinteractionComponent', () => {
  let component: UserinteractionComponent;
  let fixture: ComponentFixture<UserinteractionComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ UserinteractionComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UserinteractionComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
