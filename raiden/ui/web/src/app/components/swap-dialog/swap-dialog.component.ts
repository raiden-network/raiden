import { Observable, Subscription } from 'rxjs';
import { distinctUntilChanged, combineLatest, map, share } from 'rxjs/operators';
import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl, FormGroup, FormBuilder, Validators } from '@angular/forms';
import { SelectItem } from 'primeng/primeng';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { SwapToken } from '../../models/swaptoken';
import { TokenPipe } from '../../pipes/token.pipe';

const DIV = '/';
const TEST_CONTROLS = ['partner_address', 'identifier',
    'sending_token', 'sending_amount', 'receiving_token', 'receiving_amount'];


@Component({
    selector: 'app-swap-dialog',
    templateUrl: './swap-dialog.component.html',
    styleUrls: ['./swap-dialog.component.css']
})
export class SwapDialogComponent implements OnInit, OnDestroy {
    private subs: Subscription[] = [];

    private _visible = false;
    @Output() visibleChange: EventEmitter<boolean> = new EventEmitter<boolean>();
    public copied = false;

    public tokenAddressMapping$: Observable<SelectItem[]>;
    public form: FormGroup;
    public formString$: Observable<string>;
    public showTakerString$: Observable<boolean>;
    public takerStringFC: FormControl = new FormControl(null);

    constructor(
        private raidenService: RaidenService,
        private sharedService: SharedService,
        private fb: FormBuilder,
        private tokenPipe: TokenPipe,
    ) { }

    ngOnInit() {
        this.tokenAddressMapping$ = this.raidenService.getTokens().pipe(
            map((userTokens) => this.tokenPipe.tokensToSelectItems(userTokens)),
            share(),
        );

        this.form = this.fb.group({
            partner_address: [null, (control) =>
                control.value === this.raidenService.raidenAddress ? { ownAddress: true } : undefined],
            identifier: null,
            role: 'maker',
            sending_token: null,
            sending_amount: [null, (control) => control.value > 0 ? undefined : {invalidAmount: true}],
            receiving_token: null,
            receiving_amount: [null, (control) => control.value > 0 ? undefined : {invalidAmount: true}],
        });

        this.formString$ = this.form.valueChanges.pipe(
            combineLatest(this.form.statusChanges),
            map(([value, status]) => {
                if (!value || status !== 'VALID' || value['role'] !== 'maker' ||
                    this.form.pristine) {
                    return null;
                }
                const data = [
                    value.partner_address,
                    this.raidenService.raidenAddress,
                    value.identifier,
                    value.receiving_token,
                    value.receiving_amount,
                    value.sending_token,
                    value.sending_amount,
                ].join(DIV);
                const hash = this.raidenService.sha3(data);
                return data + DIV + hash.slice(-2);
            }),
            distinctUntilChanged(),
        );

        this.showTakerString$ = this.form.valueChanges.pipe(
            map((value) => {
                if (value.role !== 'taker') {
                    return false;
                }
                for (const field of TEST_CONTROLS) {
                    if (value[field]) {
                        return false;
                    }
                }
                return true;
            }),
        );

        this.subs.push(this.takerStringFC.valueChanges
            .subscribe((value) => this.parseFormString(value)));
    }

    ngOnDestroy() {
        this.subs.forEach((sub) => sub.unsubscribe());
    }

    get visible(): boolean {
        return this._visible;
    }

    @Input()
    set visible(v: boolean) {
        if (v === this._visible) {
            return;
        }
        this._visible = v;
        this.visibleChange.emit(v);
    }

    public accept() {
        const value: SwapToken = <SwapToken>this.form.value;
        this.raidenService.swapTokens(value)
            .subscribe(() => {
                this.sharedService.msg({
                    severity: 'success',
                    summary: value.identifier,
                    detail: value.partner_address,
                });
            });
        this.visible = false;
    }

    public reset() {
        this.form.reset({ role: this.form.get('role').value });
        this.takerStringFC.reset('');
    }

    public parseFormString(formString: string) {
        if (!formString) {
            return;
        }
        const lslash = formString.lastIndexOf(DIV);
        const data = formString.slice(0, lslash);
        const dataarray = data.split(DIV);
        const hash = this.raidenService.sha3(data);
        if (dataarray.length !== 7 || formString.slice(-2) !== hash.slice(-2)) {
            return;
        } else if (dataarray[0].toLowerCase() !== this.raidenService.raidenAddress.toLowerCase()) {
            this.sharedService.msg({
                severity: 'warn',
                summary: 'Invalid Target Address',
                detail: `Provided Token String was not targeted to your address.
                    Target address: ${dataarray[0]}.
                    Maker address: ${dataarray[1]}`,
            });
            return;
        }
        for (const field of TEST_CONTROLS) {
            this.form.get(field).markAsDirty();
            this.form.get(field).markAsTouched();
        }
        this.form.setValue({
            role: 'taker',
            partner_address: dataarray[1],
            identifier: dataarray[2],
            sending_token: dataarray[3],
            sending_amount: +dataarray[4],
            receiving_token: dataarray[5],
            receiving_amount: +dataarray[6],
        }, { emitEvent: true });
        this.takerStringFC.reset();
    }
}
