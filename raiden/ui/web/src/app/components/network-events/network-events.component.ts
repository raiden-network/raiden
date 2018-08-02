import { Component, OnInit } from '@angular/core';
import { EventsParam } from '../../models/event';

@Component({
  selector: 'app-network-events',
  templateUrl: './network-events.component.html',
  styleUrls: ['./network-events.component.css']
})
export class NetworkEventsComponent implements OnInit {

    public eventsParam: EventsParam = {
        activity: true
    };

  constructor() { }

  ngOnInit() {
  }


}
