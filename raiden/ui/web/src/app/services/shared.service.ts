import { Inject, Injectable, Injector } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import { BehaviorSubject, Observable } from 'rxjs';
import { scan } from 'rxjs/operators';

export class UiMessage {
    readonly title: string;
    readonly description: string;

    constructor(title: string, description: string) {
        this.title = title;
        this.description = description;
    }
}

@Injectable()
export class SharedService {

    public httpTimeout: number;
    private requestsSubject = new BehaviorSubject<number>(0);
    public readonly pendingRequests: Observable<number> = this.requestsSubject.asObservable()
        .pipe(
            scan((acc, value) => Math.max(acc + value, 0), 0),
        );

    constructor(@Inject(Injector) private injector: Injector) {
    }

    private get toastrService(): ToastrService {
        return this.injector.get(ToastrService);
    }

    public success(message: UiMessage) {
        this.toastrService.success(message.description, message.title);
    }

    public error(message: UiMessage) {
        this.toastrService.error(message.description, message.title);
    }

    public info(message: UiMessage) {
        this.toastrService.info(message.description, message.title);
    }

    public warn(message: UiMessage) {
        this.toastrService.warning(message.description, message.title);
    }

    requestStarted() {
        this.requestsSubject.next(+1);
    }

    requestFinished() {
        this.requestsSubject.next(-1);
    }

}
