import { TestBed, inject } from '@angular/core/testing';

import { ChannelPollingService } from './channel-polling.service';

describe('ChannelPollingService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [ChannelPollingService]
    });
  });

  it('should be created', inject([ChannelPollingService], (service: ChannelPollingService) => {
    expect(service).toBeTruthy();
  }));
});
