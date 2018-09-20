import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { APP_INITIALIZER, NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { ClipboardModule } from 'ngx-clipboard';
import { ToastrModule } from 'ngx-toastr';
import { environment } from '../environments/environment';
import { AppComponent } from './app.component';
import { ChannelTableComponent } from './components/channel-table/channel-table.component';
import { ConfirmationDialogComponent } from './components/confirmation-dialog/confirmation-dialog.component';
import { EventListComponent } from './components/event-list/event-list.component';
import { HomeComponent } from './components/home/home.component';
import { JoinDialogComponent } from './components/join-dialog/join-dialog.component';
import { LicenseComponent } from './components/license/license.component';
import { NetworkEventsComponent } from './components/network-events/network-events.component';
import { OpenDialogComponent } from './components/open-dialog/open-dialog.component';
import { PaymentDialogComponent } from './components/payment-dialog/payment-dialog.component';
import { RegisterDialogComponent } from './components/register-dialog/register-dialog.component';
import { TokenEventsComponent } from './components/token-events/token-events.component';
import { TokenNetworkComponent } from './components/token-network/token-network.component';
import { CdkDetailRowDirective } from './directives/cdk-detail-row.directive';
import { MaterialComponentsModule } from './modules/material-components/material-components.module';
import { EllipsisPipe } from './pipes/ellipsis.pipe';
import { KeysPipe } from './pipes/keys.pipe';
import { SubsetPipe } from './pipes/subset.pipe';
import { TokenPipe } from './pipes/token.pipe';
import { RaidenConfig } from './services/raiden.config';
import { RaidenInterceptor } from './services/raiden.interceptor';
import { RaidenService } from './services/raiden.service';
import { SharedService } from './services/shared.service';
import { DepositDialogComponent } from './components/deposit-dialog/deposit-dialog.component';
import { ChannelEventsComponent } from './components/channel-events/channel-events.component';
import { DecimalPipe } from './pipes/decimal.pipe';
import { TokenInputComponent } from './components/token-input/token-input.component';
import { AddressInputComponent } from './components/address-input/address-input.component';
import { TokenNetworkSelectorComponent } from './components/token-network-selector/token-network-selector.component';
import { RegisteredNetworkValidatorDirective } from './directives/registered-network-validator.directive';
import { PaymentHistoryComponent } from './components/payment-history/payment-history.component';

const appRoutes: Routes = [
    {path: '', redirectTo: '/home', pathMatch: 'full'},
    {path: 'home', component: HomeComponent},
    {path: 'license', component: LicenseComponent},
    {path: 'tokens', component: TokenNetworkComponent},
    {path: 'channels', component: ChannelTableComponent},
    {path: 'events/network', component: NetworkEventsComponent},
    {path: 'events/tokens/:address', component: TokenEventsComponent},
    {path: 'events/channels/:channel_identifier', component: ChannelEventsComponent},
    {path: 'payments', component: PaymentHistoryComponent}
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
        PaymentDialogComponent,
        JoinDialogComponent,
        RegisterDialogComponent,
        OpenDialogComponent,
        KeysPipe,
        SubsetPipe,
        TokenPipe,
        EllipsisPipe,
        NetworkEventsComponent,
        TokenEventsComponent,
        CdkDetailRowDirective,
        ConfirmationDialogComponent,
        DepositDialogComponent,
        ChannelEventsComponent,
        DecimalPipe,
        TokenInputComponent,
        AddressInputComponent,
        TokenNetworkSelectorComponent,
        RegisteredNetworkValidatorDirective,
        PaymentHistoryComponent
    ],
    imports: [
        RouterModule.forRoot(appRoutes),
        BrowserModule,
        FormsModule,
        ReactiveFormsModule,
        HttpClientModule,
        BrowserAnimationsModule,
        MaterialComponentsModule,
        ToastrModule.forRoot({
            timeOut: 5000,
            extendedTimeOut: 10000,
            preventDuplicates: true
        }),
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
        TokenPipe,
    ],
    entryComponents: [
        RegisterDialogComponent,
        JoinDialogComponent,
        PaymentDialogComponent,
        ConfirmationDialogComponent,
        DepositDialogComponent,
        OpenDialogComponent
    ],
    bootstrap: [AppComponent]
})
export class AppModule {
}
