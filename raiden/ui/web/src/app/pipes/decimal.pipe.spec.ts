import { DecimalPipe } from './decimal.pipe';

describe('DecimalPipe', () => {

    let pipe: DecimalPipe;

    beforeEach(() => {
        pipe = new DecimalPipe();
    });

    it('create an instance', () => {
        expect(pipe).toBeTruthy();
    });

    it('should show 0 when the value is 0 with 8 decimals', () => {
        expect(pipe.transform(0, 8)).toBe('0');
    });

    it('should show 1e-8 when the value is 1 with 8 decimals', () => {
        expect(pipe.transform(1, 8)).toBe('1e-8');
    });

    it('should show 1e-7 when the value is 10 with 8 decimals', () => {
        expect(pipe.transform(10, 8)).toBe('1e-7');
    });

    it('should show 0.1 when the value is 10000000 with 8 decimals', () => {
        expect(pipe.transform(10000000, 8)).toBe('0.1');
    });

    it('should show 0.1 when the value is 10000000000000000 with 18 decimals', () => {
        expect(pipe.transform(100000000000000000, 18)).toBe('0.1');
    });

    it('should show 8e-18 when the value is 8 with 18 decimals', function () {
        expect(pipe.transform(8, 18)).toBe('8e-18');
    });
});
