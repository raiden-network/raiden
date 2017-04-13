import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { MaterializeModule } from 'ng2-materialize';
import { DataTableModule, SharedModule, DataListModule, FieldsetModule } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MdTabsModule, MdInputModule, MdSelectModule } from '@angular/material';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';

import { RaidenService } from './services/raiden.service';
import { EventListComponent } from './components/event-list/event-list.component';
import { UserinteractionComponent } from './components/userinteraction/userinteraction.component';

@NgModule({
  declarations: [
    AppComponent,
    ChannelTableComponent,
    EventListComponent,
    UserinteractionComponent
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpModule,
    MaterializeModule.forRoot(),
    DataTableModule,
    SharedModule,
    DataListModule,
    FieldsetModule,
    NoopAnimationsModule,
    MdTabsModule,
    MdInputModule,
    MdSelectModule
  ],
  exports: [ MdTabsModule, MdInputModule, MdSelectModule ],
  providers: [RaidenService],
  bootstrap: [AppComponent]
})
export class AppModule { }
