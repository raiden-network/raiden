import { Component, OnInit } from '@angular/core';
import { Channel } from '../../models/channel';

@Component({
  selector: 'app-userinteraction',
  templateUrl: './userinteraction.component.html',
  styleUrls: ['./userinteraction.component.css']
})
export class UserinteractionComponent implements OnInit {

    public newChannel = new Channel();
    constructor() { }

    ngOnInit() {
    }

}
