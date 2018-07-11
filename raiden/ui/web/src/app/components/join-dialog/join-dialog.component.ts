import { Component, OnInit, OnDestroy, Input, Output, EventEmitter } from '@angular/core';
import { FormControl } from '@angular/forms';
import { Observable ,  Subscription } from 'rxjs';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';

@Component({
    selector: 'app-join-dialog',
    templateUrl: './join-dialog.component.html',
    styleUrls: ['./join-dialog.component.css']
})
export class JoinDialogComponent implements OnInit, OnDestroy {
    private subs: Subscription[] = [];

    private _visible = false;
    @Output() visibleChange: EventEmitter<boolean> = new EventEmitter<boolean>();
    @Input() tokenAddress: string;

    public funds: FormControl = new FormControl(null,
        (control) => control.value > 0 ? undefined : { invalidFund: true });

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

    public joinTokenNetwork() {
        this.raidenService.connectTokenNetwork(
            this.funds.value,
            this.tokenAddress,
        ).subscribe((response) =>
            this.sharedService.msg({
                severity: 'success',
                summary: 'Joined Token Network',
                detail: 'You have successfully Joined the Network' +
                ' of Token ' + this.tokenAddress
            })
        );
        this.visible = false;
    }

}
