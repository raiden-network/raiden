import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { EventsParam } from '../../models/event';

@Component({
    selector: 'app-token-events',
    templateUrl: './token-events.component.html',
    styleUrls: ['./token-events.component.css']
})
export class TokenEventsComponent implements OnInit {

    public eventsParam$: Observable<EventsParam>;
    public tokenAddress$: Observable<String>;

    constructor(private route: ActivatedRoute) {
    }

    ngOnInit() {
        this.tokenAddress$ = this.route.paramMap.pipe(map((params: ParamMap) => params.get('address')));
        this.eventsParam$ = this.route.paramMap.pipe(
            map((params: ParamMap) => ({
                token: params.get('address')
            }))
        );
    }

}
