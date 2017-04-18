import { Component, OnInit, Input } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { Usertoken } from '../../models/usertoken';

@Component({
  selector: 'app-token-network',
  templateUrl: './token-network.component.html',
  styleUrls: ['./token-network.component.css']
})
export class TokenNetworkComponent implements OnInit {

    @Input() raidenAddress: string;
    public tokenBalances: Usertoken[];
    public selectedToken: Usertoken;

    constructor(private raidenService: RaidenService) { }


    ngOnInit() {
        this.raidenService.getTokenBalancesOf(this.raidenAddress).subscribe(
            (balances) => {
                this.tokenBalances = <Usertoken[]> balances;
            }

        );
    }

}
