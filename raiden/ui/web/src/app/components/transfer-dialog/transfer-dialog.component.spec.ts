import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TransferDialogComponent } from './transfer-dialog.component';

describe('TransferDialogComponent', () => {
  let component: TransferDialogComponent;
  let fixture: ComponentFixture<TransferDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ TransferDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(TransferDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should be created', () => {
    expect(component).toBeTruthy();
  });
});
