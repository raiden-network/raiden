import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { DataTableModule, SharedModule, DataListModule, CarouselModule,
ButtonModule, AccordionModule } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MdTabsModule, MdInputModule, MdSelectModule, MdToolbarModule } from '@angular/material';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { FlexLayoutModule } from '@angular/flex-layout';
import { RaidenService } from './services/raiden.service';
import { EventListComponent } from './components/event-list/event-list.component';
import { UserinteractionComponent } from './components/userinteraction/userinteraction.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';

@NgModule({
  declarations: [
    AppComponent,
    ChannelTableComponent,
    EventListComponent,
    UserinteractionComponent,
    TokenNetworkComponent
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpModule,
    DataTableModule,
    SharedModule,
    DataListModule,
    CarouselModule,
    NoopAnimationsModule,
    MdTabsModule,
    MdInputModule,
    MdSelectModule,
    MdToolbarModule,
    FlexLayoutModule,
    ButtonModule,
    AccordionModule
  ],
  exports: [ MdTabsModule, MdInputModule, MdSelectModule, MdToolbarModule ],
  providers: [RaidenService],
  bootstrap: [AppComponent]
})
export class AppModule { }
