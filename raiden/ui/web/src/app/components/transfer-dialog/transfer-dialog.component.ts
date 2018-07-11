import { Observable, Subscription } from 'rxjs';
import { share, map } from 'rxjs/operators';
import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl, FormGroup, FormBuilder, Validators } from '@angular/forms';
import { SelectItem } from 'primeng/primeng';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { SwapToken } from '../../models/swaptoken';
import { TokenPipe } from '../../pipes/token.pipe';


@Component({
    selector: 'app-transfer-dialog',
    templateUrl: './transfer-dialog.component.html',
    styleUrls: ['./transfer-dialog.component.css']
})
export class TransferDialogComponent implements OnInit, OnDestroy {
    private subs: Subscription[] = [];

    private _visible = false;
    @Output() visibleChange: EventEmitter<boolean> = new EventEmitter<boolean>();
    @Input() tokenAddress: string;

    public form: FormGroup;
    public tokenAddressMapping$: Observable<SelectItem[]>;

    constructor(
        private raidenService: RaidenService,
        private sharedService: SharedService,
        private fb: FormBuilder,
        private tokenPipe: TokenPipe,
    ) { }

    ngOnInit() {
        this.form = this.fb.group({
            target_address: [null, (control) =>
                control.value === this.raidenService.raidenAddress ?
                { ownAddress: true } : undefined],
            token_address: this.tokenAddress,
            amount: [null, (control) => control.value > 0 ? undefined : {invalidAmount: true}]
        });

        this.tokenAddressMapping$ = this.raidenService.getTokens().pipe(
            map((userTokens) => this.tokenPipe.tokensToSelectItems(userTokens)),
            share(),
        );
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
        const value = this.form.value;
        this.raidenService.initiateTransfer(
            value['token_address'],
            value['target_address'],
            value['amount'],
        ).subscribe((response) => {
            if ('target_address' in response && 'identifier' in response) {
                this.sharedService.msg({
                    severity: 'success',
                    summary: 'Transfer successful',
                    detail: `${value.amount} of {value.token_address} tokens
                        where transfered to ${value.target_address}`,
                });
            } else {
                this.sharedService.msg({
                    severity: 'error',
                    summary: 'Transfer error',
                    detail: JSON.stringify(response),
                });
            }
        });
        this.visible = false;
    }

    public reset() {
        this.form.reset();
    }

}
