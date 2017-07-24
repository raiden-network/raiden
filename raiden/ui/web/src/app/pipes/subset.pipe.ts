import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
    name: 'subset'
})
export class SubsetPipe implements PipeTransform {

    transform(value: any, inc?: string | string[], exc?: string | string[]): any {
        if (inc && typeof inc === 'string') {
            inc = inc.split(',');
        }
        if (exc && typeof exc === 'string') {
            exc = exc.split(',');
        }
        return (<string[]>inc || Object.keys(value))
            .map((k) => k.trim())
            .filter((k) => k && (exc || []).indexOf(k) < 0 && value.hasOwnProperty(k))
            .reduce((o, k) => (o[k] = value[k], o), {});
    }

}
