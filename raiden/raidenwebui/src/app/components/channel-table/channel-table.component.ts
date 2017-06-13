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
    public action: string;
    public tempChannel: Channel;
    public msgs: Message[] = [];
    constructor(private route: ActivatedRoute,
                private router: Router,
                private raidenService: RaidenService,
                private sharedService: SharedService) { }

    ngOnInit() {
      this.getChannels();
    }

    public getChannels() {
        this.raidenService.getChannels().subscribe(
            (channels) => {
                this.channels = <Channel[]> channels;
                this.sharedService.setChannelData(this.channels);
            }
        );
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

    public manageChannel() {
        switch (this.action) {
            case 'transfer':
                this.raidenService.initiateTransfer(
                    this.tempChannel.token_address,
                    this.tempChannel.partner_address,
                    this.amount).subscribe(
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
        }
    }

    public showmessage(response: any) {
        this.msgs = [];
        this.msgs.push({severity: 'info', summary: 'Message', detail: JSON.stringify(response)});
    }
}
