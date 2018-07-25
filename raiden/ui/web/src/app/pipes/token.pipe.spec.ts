import { async, inject, TestBed } from '@angular/core/testing';
import { RaidenService } from '../services/raiden.service';
import { TokenPipe } from './token.pipe';

describe('TokenPipe', () => {
    let service: jasmine.SpyObj<RaidenService>;

    beforeEach(async(() => {
        service = jasmine.createSpyObj('RaidenService', [
            'getChannels'
        ]);

        TestBed.configureTestingModule({
            providers: [
                {
                    provide: RaidenService, useClass: service
                }
            ]
        }).compileComponents();
    }));


    it('create an instance', inject([RaidenService], (raidenService: RaidenService) => {
        const pipe = new TokenPipe(raidenService);
        expect(pipe).toBeTruthy();
    }));
});
