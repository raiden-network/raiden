import { Component, OnInit } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { SharedService } from '../../services/shared.service';
import { Channel } from '../../models/channel';
declare var blockies;
@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css'],
    providers: [ SharedService ]
})
export class ChannelTableComponent implements OnInit {

    public channels: Channel[];
    constructor(private raidenService: RaidenService,
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

}
