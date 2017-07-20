import { Component, OnInit, Input } from '@angular/core';
import { FormControl } from '@angular/forms';
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
    public tokenBalances: Usertoken[];
    public selectedToken: Usertoken;
    @Input() channelsToken: Channel[];
    public displayJoinDialog: boolean = false;
    public displayRegisterDialog: boolean = false;
    public channelOpened: Channel = new Channel();
    public tokenAddress: FormControl = new FormControl();
    public funds: FormControl = new FormControl();

    constructor(private raidenService: RaidenService,
                private sharedService: SharedService) { }


    ngOnInit() {
        this.raidenService.getTokenBalancesOf(this.raidenAddress).subscribe(
            (balances: Usertoken[]) => {
                this.tokenBalances = balances;
            }
        );
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
                    this.tokenBalances.push(userToken);
                    this.sharedService.msg({
                        severity: 'success',
                        summary: 'Token registered',
                        detail: 'Your token was successfully registered: ' + userToken.address,
                    });
                })
        }
        this.showRegisterDialog(false);
    }

}
