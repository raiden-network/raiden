import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl, FormGroup, FormBuilder } from '@angular/forms';
import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { SelectItem } from 'primeng/primeng';

@Component({
    selector: 'app-open-dialog',
    templateUrl: './open-dialog.component.html',
    styleUrls: ['./open-dialog.component.css']
})
export class OpenDialogComponent implements OnInit, OnDestroy {
    private subs: Subscription[] = [];

    private _visible = false;
    @Output() visibleChange: EventEmitter<boolean> = new EventEmitter<boolean>();

    public tokenAddressMapping$: Observable<SelectItem[]>;
    public form: FormGroup;

    constructor(private raidenService: RaidenService,
        private sharedService: SharedService,
        private fb: FormBuilder) { }

    ngOnInit() {
        this.tokenAddressMapping$ = this.raidenService.getTokens()
            .map((userTokens) => userTokens.map((userToken) =>
                ({
                    value: userToken.address,
                    label: userToken.name + ' (' + userToken.address + ')',
                }))
            );

        this.form = this.fb.group({
            partner_address: [null, (control) =>
                control.value === this.raidenService.raidenAddress ? { ownAddress: true } : undefined],
            token_address: null,
            balance: [null, (control) => control.value > 0 ? undefined : { invalidAmount: true }],
            settle_timeout: [600, (control) => control.value > 0 ? undefined : { invalidAmount: true }]
        });
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

    accept() {
        const value = this.form.value;
        this.raidenService.openChannel(
            value.partner_address,
            value.token_address,
            value.balance,
            value.settle_timeout)
            .subscribe((response) => {
                this.sharedService.msg({
                    severity: 'success',
                    summary: 'Channel Opened',
                    detail: `Channel with address ${response.channel_address} has been
                        created with partner ${response.partner_address}`
                });
            });
        this.visible = false;
    }
}
