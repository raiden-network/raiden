import { Component, OnInit } from '@angular/core';
import { RaidenService } from '../../services/raiden.service';
import { Event } from '../../models/event';

@Component({
    selector: 'app-event-list',
    templateUrl: './event-list.component.html',
    styleUrls: ['./event-list.component.css']
})
export class EventListComponent implements OnInit {

    public events: Event[];

    constructor(private raidenService: RaidenService) { }

    ngOnInit() {
        this.getRaidenEvents();
    }

    public getRaidenEvents() {
        this.raidenService.getEvents().subscribe(
            (events) => {
                this.events = <Event[]>events;
            }
        );
    }

}
