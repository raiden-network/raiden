import { BrowserModule } from '@angular/platform-browser';
import { NgModule, APP_INITIALIZER } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { DataTableModule, SharedModule, DataListModule, CarouselModule,
    ButtonModule, AccordionModule, GrowlModule, DialogModule, SplitButtonModule,
    TabViewModule, DropdownModule, MessagesModule, MenuModule,
    TooltipModule, RadioButtonModule,  ConfirmDialogModule,
    ConfirmationService } from 'primeng/primeng';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { ClipboardModule } from 'ngx-clipboard';

import { environment } from '../environments/environment';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { EventListComponent } from './components/event-list/event-list.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';
import { HomeComponent } from './components/home/home.component';
import { LicenseComponent } from './components/license/license.component';
import { SwapDialogComponent } from './components/swap-dialog/swap-dialog.component';
import { TransferDialogComponent } from './components/transfer-dialog/transfer-dialog.component';
import { JoinDialogComponent } from './components/join-dialog/join-dialog.component';
import { RegisterDialogComponent } from './components/register-dialog/register-dialog.component';
import { OpenDialogComponent } from './components/open-dialog/open-dialog.component';

import { SharedService } from './services/shared.service';
import { RaidenInterceptor } from './services/raiden.interceptor';
import { RaidenConfig } from './services/raiden.config';
import { RaidenService } from './services/raiden.service';
import { KeysPipe } from './pipes/keys.pipe';
import { SubsetPipe } from './pipes/subset.pipe';
import { TokenPipe } from './pipes/token.pipe';
import { EllipsisPipe } from './pipes/ellipsis.pipe';

const appRoutes: Routes = [
    { path: '', redirectTo: '/home', pathMatch: 'full' },
    { path: 'home', component: HomeComponent },
    { path: 'license', component: LicenseComponent },
    { path: 'tokens', component: TokenNetworkComponent },
    { path: 'channels', component: ChannelTableComponent },
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
        LicenseComponent,
        SwapDialogComponent,
        TransferDialogComponent,
        JoinDialogComponent,
        RegisterDialogComponent,
        OpenDialogComponent,
        KeysPipe,
        SubsetPipe,
        TokenPipe,
        EllipsisPipe,
    ],
    imports: [
        RouterModule.forRoot(appRoutes),
        BrowserModule,
        FormsModule,
        ReactiveFormsModule,
        HttpClientModule,
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
        ConfirmDialogModule,
        NoopAnimationsModule,
        ClipboardModule,
    ],
    providers: [
        SharedService,
        {
            provide: HTTP_INTERCEPTORS,
            useClass: RaidenInterceptor,
            deps: [SharedService],
            multi: true
        },
        RaidenConfig,
        {
            provide: APP_INITIALIZER,
            useFactory: ConfigLoader,
            deps: [RaidenConfig],
            multi: true
        },
        RaidenService,
        ConfirmationService,
        TokenPipe,
    ],
    bootstrap: [AppComponent]
})
export class AppModule { }
