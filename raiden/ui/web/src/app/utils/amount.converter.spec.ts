import { amountFromDecimal, amountToDecimal } from './amount.converter';

describe('AmountConverter', () => {

    it('should convert from decimal to int', function () {
        expect(amountFromDecimal(0.00000001, 8)).toBe(1);
        expect(amountFromDecimal(0.0000042, 8)).toBe(420);
        expect(amountFromDecimal(0.00003, 8)).toBe(3000);
        expect(amountFromDecimal(0.000000000000000001, 18)).toBe(1);
        expect(amountFromDecimal(0.000000000000003111, 18)).toBe(3111);
    });

    it('should convert from int to decimal', function () {
        expect(amountToDecimal(1, 8)).toBe(0.00000001);
        expect(amountToDecimal(420, 8)).toBe(0.0000042);
        expect(amountToDecimal(3000, 8)).toBe(0.00003);
        expect(amountToDecimal(3111, 18)).toBe(0.000000000000003111);
        expect(amountToDecimal(1, 18)).toBe(0.000000000000000001);
    });
});
