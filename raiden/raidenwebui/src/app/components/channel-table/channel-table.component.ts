import { Component, OnInit } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { Channel } from '../../models/channel';

@Component({
    selector: 'app-channel-table',
    templateUrl: './channel-table.component.html',
    styleUrls: ['./channel-table.component.css']
})
export class ChannelTableComponent implements OnInit {

    public channels: Channel[];
    constructor(private raidenService: RaidenService) { }

    ngOnInit() {
      this.getChannels();
    }

    public getChannels() {
        this.raidenService.getChannels().subscribe(
            (channels) => {
                this.channels = <Channel[]> channels;
            }
        );
    }


}
