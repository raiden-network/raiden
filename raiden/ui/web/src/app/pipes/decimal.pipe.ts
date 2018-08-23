import { Pipe, PipeTransform } from '@angular/core';
import { amountToDecimal } from '../utils/amount.converter';

@Pipe({
    name: 'decimal'
})
export class DecimalPipe implements PipeTransform {

    transform(value: any, decimals: number): string {
        return amountToDecimal(value, decimals).toFixed(decimals)
            .replace(/(\.\d+?)0+(?=e|$)/, '$1')
            .replace(/\.(?=e|$)/, '');
    }

}
