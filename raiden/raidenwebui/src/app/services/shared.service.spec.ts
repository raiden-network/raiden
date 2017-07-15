import { TestBed, inject } from '@angular/core/testing';

import { SharedService } from './shared.service';

describe('SharedService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [SharedService]
    });
  });

  it('should ...', inject([SharedService], (service: SharedService) => {
    expect(service).toBeTruthy();
  }));
});
