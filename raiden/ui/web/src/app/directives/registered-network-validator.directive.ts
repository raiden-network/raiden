import { Directive } from '@angular/core';
import { AbstractControl, AsyncValidator, NG_ASYNC_VALIDATORS, ValidationErrors } from '@angular/forms';
import { from, Observable } from 'rxjs';
import { defaultIfEmpty, filter, flatMap, map } from 'rxjs/operators';
import { RaidenService } from '../services/raiden.service';

@Directive({
    selector: '[registeredNetwork]',
    providers: [{provide: NG_ASYNC_VALIDATORS, useExisting: RegisteredNetworkValidatorDirective, multi: true}]
})
export class RegisteredNetworkValidatorDirective implements AsyncValidator {

    constructor(private raidenService: RaidenService) {
    }

    validate(c: AbstractControl): Promise<ValidationErrors | null> | Observable<ValidationErrors | null> {
        return this.raidenService.getTokens().pipe(
            flatMap((tokens) => from(tokens)),
            map(token => token.address),
            filter(tokenAddress => tokenAddress.toLowerCase() === c.value.toString().toLowerCase()),
            map(() => null),
            defaultIfEmpty({nonRegistered: true}),
        );
    }

}
