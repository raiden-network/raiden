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
    constructor(public raidenService: RaidenService,
                public sharedService: SharedService) { }

    ngOnInit() {
        this.raidenService.initialiseRaidenAddress()
            .subscribe((address) => this.raidenAddress = address);
    }

}
