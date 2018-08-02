import { MaterialComponentsModule } from './material-components.module';

describe('MaterialComponentsModule', () => {
  let materialComponentsModule: MaterialComponentsModule;

  beforeEach(() => {
    materialComponentsModule = new MaterialComponentsModule();
  });

  it('should create an instance', () => {
    expect(materialComponentsModule).toBeTruthy();
  });
});
