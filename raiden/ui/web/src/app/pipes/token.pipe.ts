import { Pipe, PipeTransform } from '@angular/core';
import { UserToken } from '../models/usertoken';

@Pipe({
    name: 'token'
})
export class TokenPipe implements PipeTransform {

    transform(token?: UserToken): string {
        return this.tokenToString(token);
    }

    private tokenToString(token?: UserToken): string {
        let text = '';
        if (!token) {
            return '';
        }
        if (token.symbol) {
            text += `[${token.symbol}] `;
        }
        if (token.name) {
            text += `${token.name} `;
        }
        if (text) {
            text += `(${token.address})`;
        } else {
            text = token.address;
        }
        return text;
    }

}
