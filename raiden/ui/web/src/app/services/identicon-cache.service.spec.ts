import { TestBed, inject } from '@angular/core/testing';

import { IdenticonCacheService } from './identicon-cache.service';

describe('IdenticonCacheService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [IdenticonCacheService]
    });
  });

  it('should be created', inject([IdenticonCacheService], (service: IdenticonCacheService) => {
    expect(service).toBeTruthy();
  }));
});
