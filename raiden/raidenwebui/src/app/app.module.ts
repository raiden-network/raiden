import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { DataTableModule, SharedModule, DataListModule, CarouselModule,
ButtonModule, AccordionModule, GrowlModule, DialogModule, SplitButtonModule } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MdTabsModule, MdInputModule, MdSelectModule, MdToolbarModule, MdButtonModule,
MdMenuModule } from '@angular/material';
import { RouterModule, Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { EventListComponent } from './components/event-list/event-list.component';
import { UserinteractionComponent } from './components/userinteraction/userinteraction.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';

import { APP_INITIALIZER } from '@angular/core';
import { RaidenService } from './services/raiden.service';
import { SharedService } from './services/shared.service';
import { RaidenConfig } from './services/raiden.config';
import { environment } from '../environments/environment';

const appRoutes: Routes = [
  { path: 'channels', component: ChannelTableComponent },
  { path: 'balances', component: TokenNetworkComponent }
];

@NgModule({
  declarations: [
    AppComponent,
    ChannelTableComponent,
    EventListComponent,
    UserinteractionComponent,
    TokenNetworkComponent
  ],
  imports: [
    RouterModule.forRoot(appRoutes),
    BrowserModule,
    FormsModule,
    HttpModule,
    DataTableModule,
    SharedModule,
    DataListModule,
    CarouselModule,
    ButtonModule,
    AccordionModule,
    GrowlModule,
    DialogModule,
    SplitButtonModule,
    NoopAnimationsModule,
    MdTabsModule,
    MdInputModule,
    MdSelectModule,
    MdToolbarModule,
    MdButtonModule,
    MdMenuModule,
  ],
  exports: [ MdTabsModule, MdInputModule, MdSelectModule, MdToolbarModule, MdButtonModule,
  MdMenuModule ],
  providers: [ RaidenConfig,
              {
                  provide: APP_INITIALIZER,
                  useFactory: ConfigLoader,
                  deps: [RaidenConfig],
                  multi: true
              },
              RaidenService,
              SharedService],
  bootstrap: [AppComponent]
})
export class AppModule { }

export function ConfigLoader(raidenConfig: RaidenConfig) {
    // Note: this factory need to return a function (that return a promise)
    return () => raidenConfig.load(environment.configFile);
}
