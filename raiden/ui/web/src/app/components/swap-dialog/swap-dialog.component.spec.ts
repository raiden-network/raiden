import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { SwapDialogComponent } from './swap-dialog.component';

describe('SwapDialogComponent', () => {
  let component: SwapDialogComponent;
  let fixture: ComponentFixture<SwapDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ SwapDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(SwapDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should be created', () => {
    expect(component).toBeTruthy();
  });
});
