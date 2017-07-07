import { Component, OnInit } from '@angular/core';
import { RaidenService } from './services/raiden.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent implements OnInit {
    public title = 'Raiden';
    public raidenAddress;
    constructor(private raidenService: RaidenService) {
    }

    ngOnInit() {
        this.raidenService.initialiseRaidenAddress()
            .subscribe((address) => this.raidenAddress = address);
    }


}
