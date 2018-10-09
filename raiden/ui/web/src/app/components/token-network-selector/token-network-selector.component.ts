import { Component, EventEmitter, forwardRef, OnInit, Output } from '@angular/core';
import {
    AbstractControl,
    ControlValueAccessor,
    FormControl,
    NG_VALIDATORS,
    NG_VALUE_ACCESSOR,
    ValidationErrors,
    Validator,
    ValidatorFn
} from '@angular/forms';
import { Observable } from 'rxjs';
import { flatMap, map, share, startWith } from 'rxjs/operators';
import { UserToken } from '../../models/usertoken';
import { RaidenService } from '../../services/raiden.service';
import { amountToDecimal } from '../../utils/amount.converter';

@Component({
    selector: 'app-token-network-selector',
    templateUrl: './token-network-selector.component.html',
    styleUrls: ['./token-network-selector.component.css'],
    providers: [
        {
            provide: NG_VALUE_ACCESSOR,
            useExisting: forwardRef(() => TokenNetworkSelectorComponent),
            multi: true
        },
        {
            provide: NG_VALIDATORS,
            useExisting: forwardRef(() => TokenNetworkSelectorComponent),
            multi: true
        }
    ]
})
export class TokenNetworkSelectorComponent implements OnInit, ControlValueAccessor, Validator {

    @Output() valueChanged = new EventEmitter<UserToken>();
    public filteredOptions$: Observable<UserToken[]>;
    readonly tokenFc = new FormControl('', [this.addressValidatorFn(this.raidenService)]);
    private tokens$: Observable<UserToken[]>;

    constructor(private raidenService: RaidenService) {
    }

    ngOnInit() {
        this.tokens$ = this.raidenService.getTokens().pipe(
            map(value => value.sort(this._compareTokens)),
            share()
        );

        this.filteredOptions$ = this.tokenFc.valueChanges.pipe(
            startWith(''),
            flatMap(value => this._filter(value))
        );
    }

    // noinspection JSMethodCanBeStatic
    trackByFn(token: UserToken): string {
        return token.address;
    }

    tokenSelected(value: UserToken) {
        this.tokenFc.setValue(value.address);
    }

    registerOnChange(fn: any): void {
        this.tokenFc.valueChanges.subscribe(fn);
    }

    registerOnTouched(fn: any): void {
        this.tokenFc.registerOnChange(fn);
    }

    registerOnValidatorChange(fn: () => void): void {

    }

    setDisabledState(isDisabled: boolean): void {
        if (isDisabled) {
            this.tokenFc.disable();
        } else {
            this.tokenFc.enable();
        }
    }

    validate(c: AbstractControl): ValidationErrors | null {
        if (!this.tokenFc.value) {
            return {empty: true};
        }

        const errors = this.tokenFc.errors;
        if (!errors) {
            this.raidenService.getUserToken(c.value).subscribe(value => this.valueChanged.emit(value));
        }
        return errors;
    }

    writeValue(obj: any): void {
        if (!obj) {
            return;
        }
        this.tokenFc.setValue(obj, {emitEvent: false});
    }

    checksum(): string {
        return this.raidenService.toChecksumAddress(this.tokenFc.value);
    }

    // noinspection JSMethodCanBeStatic
    private _compareTokens(a: UserToken, b: UserToken): number {
        const aConnected = !!a.connected;
        const bConnected = !!b.connected;
        if (aConnected === bConnected) {
            return amountToDecimal(b.balance, b.decimals) - amountToDecimal(a.balance, a.decimals);
        } else {
            return aConnected ? -1 : 1;
        }
    }

    private _filter(value?: string): Observable<UserToken[]> {
        if (!value || typeof value !== 'string') {
            return this.tokens$;
        }

        const keyword = value.toLowerCase();

        function matches(token: UserToken) {
            const name = token.name.toLocaleLowerCase();
            const symbol = token.symbol.toLocaleLowerCase();
            const address = token.address.toLocaleLowerCase();
            return name.startsWith(keyword) || symbol.startsWith(keyword) || address.startsWith(keyword);
        }

        return this.tokens$.pipe(map((tokens: UserToken[]) => tokens.filter(matches)));
    }

    private addressValidatorFn(raidenService: RaidenService): ValidatorFn {
        return (control: AbstractControl) => {
            const controlValue = control.value;
            if (controlValue && controlValue.length === 42 && !raidenService.checkChecksumAddress(controlValue)) {
                return {notChecksumAddress: true};
            } else {
                return undefined;
            }
        };
    }
}
