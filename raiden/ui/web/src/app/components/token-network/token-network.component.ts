import { Component, OnInit, Input } from '@angular/core';
import { FormControl } from '@angular/forms';
import { Observable } from 'rxjs/Observable';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';

import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Usertoken } from '../../models/usertoken';
import { Message } from 'primeng/primeng';
import { Channel } from '../../models/channel';

@Component({
    selector: 'app-token-network',
    templateUrl: './token-network.component.html',
    styleUrls: ['./token-network.component.css']
})
export class TokenNetworkComponent implements OnInit {

    @Input() raidenAddress: string;
    @Input() channelsToken: Channel[];

    private tokensSubject: BehaviorSubject<void> = new BehaviorSubject(null);
    public tokensBalances$: Observable<Usertoken[]>;
    public selectedToken: Usertoken;
    public refreshing = false;

    public displayJoinDialog = false;
    public displayRegisterDialog = false;
    public displaySwapDialog = false;
    public displayTransferDialog = false;
    public channelOpened: Channel = {};
    public tokenAddress: FormControl = new FormControl();
    public funds: FormControl = new FormControl();

    constructor(private raidenService: RaidenService,
                private sharedService: SharedService) { }


    ngOnInit() {
        this.tokensBalances$ = this.tokensSubject
            .do(() => this.refreshing = true)
            .switchMap(() => this.raidenService.getTokensBalances()
                .finally(() => this.refreshing = false));
    }

    public showJoinDialogBox() {
        console.log('Inside Join Token Network');
        if (this.selectedToken == null) {
            this.sharedService.msg({
                severity: 'error',
                summary: 'Token Not Selected',
                detail: 'Please select a token network to Join'
              });
              return;
        }
        if (this.selectedToken.balance === 0) {
            this.sharedService.msg({
                severity: 'error',
                summary: 'Insufficient Balance',
                detail: 'Your Balance in this token network is zero.'
            });
            return;
        }
        this.displayJoinDialog = true;
        this.funds.reset();
    }

    public joinTokenNetwork() {
        this.raidenService.connectTokenNetwork(this.funds.value,
            this.selectedToken.address).subscribe(
                (response) => {
                    if (response.status === 200) {
                        this.sharedService.msg({
                            severity: 'success',
                            summary: 'Joined Token Network',
                            detail: 'You have successfully Joined the Network' +
                            ' of Token ' + this.selectedToken.address
                        });
                    } else if (response.status === 500) {
                        this.sharedService.msg({
                            severity: 'error',
                            summary: 'Server Error',
                            detail: 'Server has encountered Internal Error'
                        })
                    }
                }
          );
          this.displayJoinDialog = false;
          this.funds.reset();
    }

    public showRegisterDialog(show: boolean) {
        this.tokenAddress.reset();
        this.displayRegisterDialog = show;
    }

    public registerToken() {
        if (this.tokenAddress.value && /^0x[0-9a-f]{40}$/i.test(this.tokenAddress.value)) {
            this.raidenService.registerToken(this.tokenAddress.value)
                .subscribe((userToken: Usertoken) => {
                    this.refreshTokens();
                    this.sharedService.msg({
                        severity: 'success',
                        summary: 'Token registered',
                        detail: 'Your token was successfully registered: ' + userToken.address,
                    });
                })
        }
        this.showRegisterDialog(false);
    }

    public refreshTokens() {
        this.tokensSubject.next(null);
    }

    public showSwapDialog(show: boolean = true) {
        this.displaySwapDialog = show;
    }

    public showTransferDialog(show: boolean = true) {
        this.displayTransferDialog = show;
    }

}
