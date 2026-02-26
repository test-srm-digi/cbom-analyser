/**
 * Redux Store — configured with RTK Query middleware
 */
import { configureStore } from '@reduxjs/toolkit';
import { integrationsApi } from './api/integrationsApi';
import { certificatesApi } from './api/certificatesApi';
import { endpointsApi } from './api/endpointsApi';
import { softwareApi } from './api/softwareApi';
import { devicesApi } from './api/devicesApi';
import { codeFindingsApi } from './api/codeFindingsApi';
import { cbomImportsApi } from './api/cbomImportsApi';

export const store = configureStore({
  reducer: {
    [integrationsApi.reducerPath]: integrationsApi.reducer,
    [certificatesApi.reducerPath]: certificatesApi.reducer,
    [endpointsApi.reducerPath]: endpointsApi.reducer,
    [softwareApi.reducerPath]: softwareApi.reducer,
    [devicesApi.reducerPath]: devicesApi.reducer,
    [codeFindingsApi.reducerPath]: codeFindingsApi.reducer,
    [cbomImportsApi.reducerPath]: cbomImportsApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware()
      .concat(integrationsApi.middleware)
      .concat(certificatesApi.middleware)
      .concat(endpointsApi.middleware)
      .concat(softwareApi.middleware)
      .concat(devicesApi.middleware)
      .concat(codeFindingsApi.middleware)
      .concat(cbomImportsApi.middleware),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
