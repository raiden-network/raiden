import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl } from '@angular/forms';
import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Usertoken } from '../../models/usertoken';

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

    constructor(private raidenService: RaidenService,
        private sharedService: SharedService) { }

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

    public registerToken() {
        if (this.tokenAddress.value && /^0x[0-9a-f]{40}$/i.test(this.tokenAddress.value)) {
            this.raidenService.registerToken(this.tokenAddress.value)
                .subscribe((userToken: Usertoken) => {
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
