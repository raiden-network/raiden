import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FlexLayoutModule } from '@angular/flex-layout';
import {
    MatAutocompleteModule,
    MatBadgeModule,
    MatButtonModule,
    MatCardModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatListModule,
    MatMenuModule,
    MatPaginatorModule,
    MatProgressSpinnerModule,
    MatRadioModule,
    MatRippleModule,
    MatSelectModule,
    MatSidenavModule,
    MatSortModule,
    MatTableModule,
    MatToolbarModule,
    MatTooltipModule
} from '@angular/material';

@NgModule({
    exports: [
        FlexLayoutModule,
        MatFormFieldModule,
        MatMenuModule,
        MatIconModule,
        MatButtonModule,
        MatPaginatorModule,
        MatCardModule,
        MatSelectModule,
        MatInputModule,
        MatListModule,
        MatTooltipModule,
        MatDialogModule,
        MatProgressSpinnerModule,
        MatToolbarModule,
        MatAutocompleteModule,
        MatTableModule,
        MatRippleModule,
        MatSortModule,
        MatSidenavModule,
        MatBadgeModule,
        MatRadioModule
    ],
    imports: [
        CommonModule
    ],
    declarations: []
})
export class MaterialComponentsModule {
}
