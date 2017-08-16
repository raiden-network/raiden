import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { OpenDialogComponent } from './open-dialog.component';

describe('OpenDialogComponent', () => {
  let component: OpenDialogComponent;
  let fixture: ComponentFixture<OpenDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ OpenDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(OpenDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should be created', () => {
    expect(component).toBeTruthy();
  });
});
