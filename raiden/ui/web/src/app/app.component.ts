import { Component, OnInit } from '@angular/core';
import { RaidenService } from './services/raiden.service';
import { SharedService } from './services/shared.service';

@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.css'],
})
export class AppComponent implements OnInit {
    public title = 'Raiden';
    public raidenAddress;
    public menuCollapsed = false;

    constructor(public sharedService: SharedService,
                public raidenService: RaidenService) { }

    ngOnInit() {
        this.raidenService.getRaidenAddress()
            .subscribe((address) => this.raidenAddress = address);
    }

}
