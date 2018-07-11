import { Observable, Subscription } from 'rxjs';
import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl } from '@angular/forms';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { UserToken } from '../../models/usertoken';

@Component({
    selector: 'app-register-dialog',
    templateUrl: './register-dialog.component.html',
    styleUrls: ['./register-dialog.component.css']
})
export class RegisterDialogComponent implements OnInit, OnDestroy {
    private subs: Subscription[] = [];

    private _visible = false;
    @Output() visibleChange: EventEmitter<boolean> = new EventEmitter<boolean>();
    @Output() tokensChange: EventEmitter<void> = new EventEmitter<void>(null);

    public tokenAddress: FormControl = new FormControl();

    public notAChecksumAddress() {
        if (this.tokenAddress.valid && this.tokenAddress.value.length > 0) {
            return !this.raidenService.checkChecksumAddress(this.tokenAddress.value);
        }
    }

    constructor(
        private raidenService: RaidenService,
        private sharedService: SharedService,
    ) { }

    ngOnInit() {
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

    public convertToChecksum(): string {
        return 'Not a checksum address, try \n"' + this.raidenService.toChecksumAddress(this.tokenAddress.value) + '" instead.';
    }

    public registerToken() {
        if (this.tokenAddress.value && /^0x[0-9a-f]{40}$/i.test(this.tokenAddress.value)) {
            this.raidenService.registerToken(
                this.tokenAddress.value,
            ).subscribe((userToken: UserToken) => {
                this.tokensChange.emit(null);
                this.sharedService.msg({
                    severity: 'success',
                    summary: 'Token registered',
                    detail: 'Your token was successfully registered: ' + userToken.address,
                });
            });
        }
        this.visible = false;
    }

}
