import { TestBed, inject } from '@angular/core/testing';

import { BalanceCheckerService } from './balance-checker.service';

describe('BalanceCheckerService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [BalanceCheckerService]
    });
  });

  it('should be created', inject([BalanceCheckerService], (service: BalanceCheckerService) => {
    expect(service).toBeTruthy();
  }));
});
