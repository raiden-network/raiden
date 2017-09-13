import { MenuItem } from 'primeng/primeng';

export type WithMenu<T> = T & { menu: MenuItem[] };
