import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { ChannelInformation, EventsParam } from '../../models/event';


@Component({
    selector: 'app-channel-events',
    templateUrl: './channel-events.component.html',
    styleUrls: ['./channel-events.component.css']
})
export class ChannelEventsComponent implements OnInit {

    public eventsParam$: Observable<EventsParam>;
    public channelIdentifier$: Observable<number>;

    constructor(private route: ActivatedRoute) {
    }

    ngOnInit() {
        const channelIdentifierOperator = map((params: ParamMap) => parseInt(params.get('channel_identifier'), 10));
        this.channelIdentifier$ = this.route.paramMap.pipe(channelIdentifierOperator);
        this.eventsParam$ = this.route.queryParamMap.pipe(
            map((params: ParamMap) => {
                const channelInformation: ChannelInformation = {
                    token_address: params.get('token_address'),
                    partner_address: params.get('partner_address')
                };

                return {
                    channel: channelInformation
                };
            })
        );
    }

}
