import { BrowserModule } from '@angular/platform-browser';
import { NgModule, APP_INITIALIZER } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpModule, Http } from '@angular/http';
import { DataTableModule, SharedModule, DataListModule, CarouselModule,
    ButtonModule, AccordionModule, GrowlModule, DialogModule, SplitButtonModule,
    TabViewModule, DropdownModule, MessagesModule, MenuModule,
    TooltipModule, RadioButtonModule } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { ClipboardModule } from 'ngx-clipboard';

import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { EventListComponent } from './components/event-list/event-list.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';
import { HomeComponent } from './components/home/home.component';
import { SwapDialogComponent } from './components/swap-dialog/swap-dialog.component';
import { TransferDialogComponent } from './components/transfer-dialog/transfer-dialog.component';

import { RaidenConfig } from './services/raiden.config';
import { SharedService } from './services/shared.service';
import { RaidenService } from './services/raiden.service';
import { environment } from '../environments/environment';
import { KeysPipe } from './pipes/keys.pipe';
import { SubsetPipe } from './pipes/subset.pipe';

const appRoutes: Routes = [
    { path: 'home', component: HomeComponent },
    { path: '', redirectTo: '/home', pathMatch: 'full' },
    { path: 'channels', component: ChannelTableComponent },
    { path: 'balances', component: TokenNetworkComponent }
];

export function ConfigLoader(raidenConfig: RaidenConfig) {
    // Note: this factory need to return a function (that return a promise)
    return () => raidenConfig.load(environment.configFile);
}

@NgModule({
    declarations: [
        AppComponent,
        ChannelTableComponent,
        EventListComponent,
        TokenNetworkComponent,
        HomeComponent,
        SwapDialogComponent,
        KeysPipe,
        SubsetPipe,
        TransferDialogComponent,
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
        TooltipModule,
        RadioButtonModule,
        NoopAnimationsModule,
        ClipboardModule,
    ],
    providers: [
        RaidenConfig,
        {
            provide: APP_INITIALIZER,
            useFactory: ConfigLoader,
            deps: [RaidenConfig],
            multi: true
        },
        SharedService,
        RaidenService,
    ],
    bootstrap: [AppComponent]
})
export class AppModule { }
