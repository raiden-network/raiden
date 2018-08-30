import { animate, state, style, transition, trigger } from '@angular/animations';
import { Component, EventEmitter, Input, OnInit, Output, ViewChild } from '@angular/core';
import { MatPaginator, MatSort, MatTableDataSource } from '@angular/material';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { map, scan, switchMap, tap } from 'rxjs/operators';
import { CdkDetailRowDirective } from '../../directives/cdk-detail-row.directive';
import { Event, EventsParam } from '../../models/event';

import { RaidenConfig } from '../../services/raiden.config';
import { RaidenService } from '../../services/raiden.service';

@Component({
    selector: 'app-event-list',
    templateUrl: './event-list.component.html',
    styleUrls: ['./event-list.component.css'],
    animations: [
        trigger('detailExpand', [
            state('void', style({height: '0px', minHeight: '0', visibility: 'hidden'})),
            state('*', style({height: '*', visibility: 'visible'})),
            transition('void <=> *', animate('225ms cubic-bezier(0.4, 0.0, 0.2, 1)')),
        ]),
    ]
})
export class EventListComponent implements OnInit {

    displayedColumns = ['block_number', 'timestamp', 'event', 'data'];
    dataSource: MatTableDataSource<Event>;
    @ViewChild(MatPaginator) paginator: MatPaginator;
    @ViewChild(MatSort) sort: MatSort;
    @Input() eventsParam: EventsParam;
    @Output() activity: EventEmitter<void> = new EventEmitter<void>();
    public events$: Observable<Event[]>;
    public loading = true;

    private openedRow: CdkDetailRowDirective;

    constructor(
        private raidenConfig: RaidenConfig,
        private raidenService: RaidenService
    ) {
        this.dataSource = new MatTableDataSource();
    }

    onToggleChange(cdkDetailRow: CdkDetailRowDirective): void {
        if (this.openedRow && this.openedRow.expended) {
            this.openedRow.toggle();
        }
        this.openedRow = cdkDetailRow.expended ? cdkDetailRow : undefined;
    }

    ngOnInit() {
        this.dataSource.paginator = this.paginator;
        this.dataSource.sort = this.sort;

        let fromBlock: number = this.raidenConfig.config.block_start;
        let first = true;

        const data_excl = ['event', 'block_number', 'timestamp'];
        const firerSub: BehaviorSubject<void> = new BehaviorSubject(null);
        this.events$ = firerSub.pipe(
            tap(() => this.loading = true),
            switchMap(() => this.raidenService.getBlockNumber()),
            switchMap((latestBlock) => {
                if (fromBlock > latestBlock) {
                    return of([]);
                }
                const obs = this.raidenService.getBlockchainEvents(
                    this.eventsParam,
                    fromBlock,
                    latestBlock);
                fromBlock = latestBlock + 1;
                return obs;
            }),
            map((events) => events.map((event) =>
                <Event>Object.assign(event,
                    {
                        data: JSON.stringify(
                            Object.keys(event)
                                .filter((k) => data_excl.indexOf(k) < 0)
                                .reduce((o, k) => (o[k] = event[k], o), {})
                        )
                    }
                ))
            ),
            tap((newEvents: Event[]) => {
                if (newEvents.length > 0 && !first) {
                    this.activity.emit();
                }
                first = false;
            }),
            scan((oldEvents, newEvents) => {
                // this scan/reducer agregates new events (since next_block) with old ones,
                // updating next_block if needed. If no next_block previously,
                // it means it fetched all events, so use only newEvents
                newEvents.reverse(); // most recent first
                const events = !first ? [...newEvents, ...oldEvents] :
                    newEvents.length > 0 ? newEvents : oldEvents;
                for (const event of events) {
                    if (event.block_number > 0 && !event.timestamp) {
                        this.raidenService.blocknumberToDate(event.block_number)
                            .subscribe((date) => event.timestamp = date);
                    }
                }
                return events;
            }, []),
            tap(() => setTimeout(() => firerSub.next(null), this.raidenConfig.config.poll_interval)),
            tap(() => this.loading = false),
        );

        this.events$.subscribe((events: Event[]) => this.dataSource.data = events);

    }

    applyFilter(filterValue: string) {
        this.dataSource.filter = filterValue.trim().toLowerCase();

        if (this.dataSource.paginator) {
            this.dataSource.paginator.firstPage();
        }
    }

    // noinspection JSMethodCanBeStatic
    trackByFn(index, item: Event) {
        return item.block_number + item.event + item.timestamp;
    }
}
