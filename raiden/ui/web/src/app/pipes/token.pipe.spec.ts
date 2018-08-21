import { UserToken } from '../models/usertoken';
import { TokenPipe } from './token.pipe';

describe('TokenPipe', () => {

    let pipe: TokenPipe;

    let token: UserToken;

    beforeEach(() => {
        pipe = new TokenPipe();
        token = {
            address: '0x0f114A1E9Db192502E7856309cc899952b3db1ED',
            symbol: 'TST',
            name: 'Test Suite Token',
            balance: 20,
            decimals: 8
        };
    });

    it('create an instance', () => {
        expect(pipe).toBeTruthy();
    });

    it('should convert a user token to a string representation', () => {
        const tokenString = pipe.transform(token);
        expect(tokenString).toBe(`[${token.symbol}] ${token.name} (${token.address})`);
    });

    it('should have the following format if symbol is missing', () => {
        token.symbol = null;
        const tokenString = pipe.transform(token);
        expect(tokenString).toBe(`${token.name} (${token.address})`);
    });

    it('should have the following format if only address is available', () => {
        token.symbol = null;
        token.name = null;
        const tokenString = pipe.transform(token);
        expect(tokenString).toBe(token.address);
    });

});
