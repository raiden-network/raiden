import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { JoinDialogComponent } from './join-dialog.component';

describe('JoinDialogComponent', () => {
  let component: JoinDialogComponent;
  let fixture: ComponentFixture<JoinDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ JoinDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(JoinDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should be created', () => {
    expect(component).toBeTruthy();
  });
});
