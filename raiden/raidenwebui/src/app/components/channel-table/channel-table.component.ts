import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute, Params } from '@angular/router';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Channel } from '../../models/channel';
import { MenuModule, MenuItem, Message} from 'primeng/primeng';
declare var blockies;
@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
    providers: [ SharedService ]
})
export class ChannelTableComponent implements OnInit {

    public channels: Channel[];
    public items: MenuItem[];
    public amount: number;
    public displayDialog: boolean;
    public displayChannelDialog: boolean;
    public action: string;
    public tempChannel: Channel = new Channel();
    public msgs: Message[] = [];
    public tokenAddressMapping: Array<{ value: string, label: string}>;
    constructor(private route: ActivatedRoute,
                private router: Router,
                private raidenService: RaidenService,
                private sharedService: SharedService) { }

    ngOnInit() {
      this.getChannels();
      this.getTokenNameAddresMappings();
    }

    public getChannels() {
        this.raidenService.getChannels().subscribe(
            (channels) => {
                this.channels = <Channel[]> channels;
                this.sharedService.setChannelData(this.channels);
            }
        );
    }

    public getTokenNameAddresMappings() {
      this.raidenService.getTokenNameAddresMappings().subscribe(
          (mappings) => {
              this.tokenAddressMapping = mappings;
          });
    }

    public generateBlockies(icon: any, address: string) {
        console.log(address);
        icon.style.backgroundImage = 'url(' + blockies.create({ seed: address , size: 8, scale: 16})
        .toDataURL() + ')';
    }

    public onTransfer(channel: Channel) {
        this.action = 'transfer';
        this.tempChannel = channel;
        this.displayDialog = true;
    }

    public onDeposit(channel: Channel) {
        this.action = 'deposit';
        this.tempChannel = channel;
        this.displayDialog = true;
    }

    public onClose(channel: Channel) {
        this.action = 'close';
        this.tempChannel = channel;
        this.manageChannel();
    }

    public onSettle(channel: Channel) {
        this.action = 'settle';
        this.tempChannel = channel;
        this.manageChannel();
    }

    public onOpen() {
        this.action = 'open';
        this.tempChannel = new Channel();
        this.displayChannelDialog = true;
    }

    public manageChannel() {
        this.displayDialog = false;
        this.displayChannelDialog = false;
        switch (this.action) {
            case 'transfer':
                this.raidenService.initiateTransfer(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                    this.amount,
                    Math.floor(Math.random() * 101)).subscribe(
                        (response) => {
                            this.showmessage(response);
                        }
                    );
                break;
            case 'deposit':
                this.raidenService.depositToChannel(
                    this.tempChannel.channel_address,
                    this.amount).subscribe((response) => {
                        this.showmessage(response);
                    });
                break;
            case 'close':
                this.raidenService.closeChannel(this.tempChannel.channel_address)
                .subscribe((response) => {
                    this.showmessage(response);
                });
                break;
            case 'settle':
                this.raidenService.settleChannel(this.tempChannel.channel_address)
                .subscribe((response) => {
                    this.showmessage(response);
                });
            break;
            case 'open':
                console.log('inside open');
                this.raidenService.openChannel(
                    this.tempChannel.partner_address,
                    this.tempChannel.token_address,
                    this.tempChannel.balance,
                    this.tempChannel.settle_timeout)
                .subscribe((response) => {
                    console.log('logging the response');
                    console.log(response);
                    this.showmessage(response);
                });
            break;
        }
    }

    public showmessage(response: any) {
        this.msgs = [];
        this.msgs.push({severity: 'info', summary: 'Message', detail: JSON.stringify(response)});
    }
}
