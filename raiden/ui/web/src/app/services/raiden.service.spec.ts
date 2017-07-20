import { TestBed, inject } from '@angular/core/testing';

import { RaidenService } from './raiden.service';

describe('RaidenService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [RaidenService]
    });
  });

  it('should ...', inject([RaidenService], (service: RaidenService) => {
    expect(service).toBeTruthy();
  }));
});
