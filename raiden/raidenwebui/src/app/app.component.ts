import { Component } from '@angular/core';
import { RaidenService } from './services/raiden.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent {
    public title = 'Raiden';
    public raidenAddress;
    constructor(private raidenService: RaidenService) {
        this.raidenAddress = raidenService.getRaidenAddress();
    }

}
