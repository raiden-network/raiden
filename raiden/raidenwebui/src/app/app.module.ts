import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { DataTableModule, SharedModule, DataListModule, CarouselModule,
    ButtonModule, AccordionModule, GrowlModule, DialogModule, SplitButtonModule,
    TabViewModule, DropdownModule, MessagesModule, MenuModule } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { EventListComponent } from './components/event-list/event-list.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';

import { APP_INITIALIZER } from '@angular/core';
import { RaidenService } from './services/raiden.service';
import { SharedService } from './services/shared.service';
import { RaidenConfig } from './services/raiden.config';
import { environment } from '../environments/environment';
import { HomeComponent } from './components/home/home.component';

const appRoutes: Routes = [
  { path: 'home', component: HomeComponent},
  { path: '', redirectTo: '/home', pathMatch: 'full'},
  { path: 'channels', component: ChannelTableComponent },
  { path: 'balances', component: TokenNetworkComponent }
];

@NgModule({
  declarations: [
    AppComponent,
    ChannelTableComponent,
    EventListComponent,
    TokenNetworkComponent,
    HomeComponent
  ],
  imports: [
    RouterModule.forRoot(appRoutes),
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
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
    TabViewModule,
    DropdownModule,
    MessagesModule,
    MenuModule,
    NoopAnimationsModule,
  ],
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
