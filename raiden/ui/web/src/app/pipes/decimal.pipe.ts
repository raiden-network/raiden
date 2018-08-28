import { Pipe, PipeTransform } from '@angular/core';
import BigNumber from 'bignumber.js';
import { amountToDecimal } from '../utils/amount.converter';

@Pipe({
    name: 'decimal'
})
export class DecimalPipe implements PipeTransform {

    transform(value: any, decimals: number): string {
        const amount = new BigNumber(amountToDecimal(value, decimals));
        return !amount.isZero() ? amount.toString() : '0';
    }

}
