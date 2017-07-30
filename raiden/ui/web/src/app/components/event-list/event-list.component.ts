import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { Observable } from 'rxjs/Observable';

import { Event, EventsParam } from '../../models/event';

const INTERVAL = 5000;

@Component({
    selector: 'app-event-list',
    templateUrl: './event-list.component.html',
    styleUrls: ['./event-list.component.css']
})
export class EventListComponent implements OnInit {

    @Input() eventsParam: EventsParam;
    @Output() activity: EventEmitter<void> = new EventEmitter<void>();

    public events$: Observable<Event[]>;

    constructor(private raidenService: RaidenService) { }

    ngOnInit() {
        let next_block: number | undefined;
        const data_excl = ['event_type', 'block_number', 'timestamp'];
        this.events$ = Observable.timer(0, INTERVAL)
            .switchMap(() => this.raidenService.getEvents(this.eventsParam, next_block))
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
                if (newEvents.length > 0) {
                    this.activity.emit();
                }
            })
            .scan((oldEvents, newEvents) => {
                // this scan/reducer agregates new events (since next_block) with old ones,
                // updating next_block if needed. If no next_block previously,
                // it means it fetched all events, so use only newEvents
                newEvents.reverse(); // most recent first
                const events = next_block ? [...newEvents, ...oldEvents] :
                    newEvents.length > 0 ? newEvents : oldEvents;
                const max_block = Math.max(
                    ...newEvents
                        .map((event) => event.block_number)
                        .filter((block_number) => !isNaN(block_number))
                );
                if (max_block > 0) {
                    next_block = max_block + 1;
                }
                for (const event of events) {
                    if (event.block_number > 0 && !event.timestamp) {
                        this.raidenService.blocknumberToDate(event.block_number)
                            .subscribe((date) => event.timestamp = date);
                    }
                }
                return events;
            }, []);
    }
}
