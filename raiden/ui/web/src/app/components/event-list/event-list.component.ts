import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';

import { RaidenService } from '../../services/raiden.service';
import { Event, EventsParam } from '../../models/event';

const INTERVAL = 5000;
const BLOCK_START = 1422953; // block where the registry contract was deployed

@Component({
    selector: 'app-event-list',
    templateUrl: './event-list.component.html',
    styleUrls: ['./event-list.component.css']
})
export class EventListComponent implements OnInit {

    @Input() eventsParam: EventsParam;
    @Output() activity: EventEmitter<void> = new EventEmitter<void>();

    public events$: Observable<Event[]>;
    public loading = true;

    constructor(private raidenService: RaidenService) { }

    ngOnInit() {
        let from: number = BLOCK_START;
        let first = true;
        const data_excl = ['event_type', 'block_number', 'timestamp'];
        const firerSub: BehaviorSubject<void> = new BehaviorSubject(null);
        this.events$ = firerSub
            .do(() => this.loading = true)
            .switchMap(() => this.raidenService.getEvents(
                    this.eventsParam,
                    from)
                .finally(() => this.loading = false))
            .map((events) => events.map((event) =>
                <Event>Object.assign(event,
                    {
                        data: JSON.stringify(Object.keys(event)
                            .filter((k) => data_excl.indexOf(k) < 0)
                            .reduce((o, k) => (o[k] = event[k], o), {}))
                    }
                ))
            )
            .do((newEvents) => {
                if (newEvents.length > 0 && !first) {
                    this.activity.emit();
                }
                first = false;
                from = this.raidenService.blockNumber + 1;
            })
            .scan((oldEvents, newEvents) => {
                // this scan/reducer agregates new events (since next_block) with old ones,
                // updating next_block if needed. If no next_block previously,
                // it means it fetched all events, so use only newEvents
                newEvents.reverse(); // most recent first
                const events = !first ? [...newEvents, ...oldEvents] :
                    newEvents.length > 0 ? newEvents : oldEvents;
                for (const event of events) {
                    if (event.block_number > 0 && !event.timestamp) {
                        this.raidenService.blocknumberToDate(event.block_number)
                            .subscribe((date) => event.timestamp = date);
                    }
                }
                return events;
            }, [])
            .do(() => setTimeout(() => firerSub.next(null), INTERVAL));
    }
}
