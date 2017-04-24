import { Component, OnInit, Input } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Usertoken } from '../../models/usertoken';
import {Message} from 'primeng/primeng';
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
    public msgs: Message[] = [];
    @Input() channelsToken: Channel[];
    public displayDialog: boolean = false;
    public channelOpened: Channel = new Channel();
    constructor(private raidenService: RaidenService,
    private sharedService: SharedService) { }


    ngOnInit() {
        this.raidenService.getTokenBalancesOf(this.raidenAddress).subscribe(
            (balances) => {
                this.tokenBalances = <Usertoken[]> balances;
            }

        );
    }

    public joinTokenNetwork() {
        if (this.selectedToken.balance === 0) {
            this.msgs.push({
                severity: 'error',
                summary: 'Insufficient Balance',
                detail: 'Your Balance in this token network is zero.'
            });
            return;
        }
        for (const channel of this.channelsToken) {
            if (this.selectedToken.address === channel.token_address) {
                this.msgs.push({
                    severity: 'warn',
                    summary: 'Warining message',
                    detail: 'You already participate in this token network'
                });
                return;
            }
        }
        this.displayDialog = true;
    }

}
