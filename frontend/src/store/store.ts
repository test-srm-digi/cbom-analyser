/**
 * Redux Store — configured with RTK Query middleware
 */
import { configureStore } from '@reduxjs/toolkit';
import { integrationsApi } from './api/integrationsApi';
import { certificatesApi } from './api/certificatesApi';
import { endpointsApi } from './api/endpointsApi';
import { softwareApi } from './api/softwareApi';
import { devicesApi } from './api/devicesApi';
import { cbomImportsApi } from './api/cbomImportsApi';
import { syncLogsApi } from './api/syncLogsApi';
import { schedulerApi } from './api/schedulerApi';
import { policiesApi } from './api/policiesApi';
import { trackingApi } from './api/trackingApi';
import { xbomApi } from './api/xbomApi';
import { cbomUploadsApi } from './api/cbomUploadsApi';

export const store = configureStore({
  reducer: {
    [integrationsApi.reducerPath]: integrationsApi.reducer,
    [certificatesApi.reducerPath]: certificatesApi.reducer,
    [endpointsApi.reducerPath]: endpointsApi.reducer,
    [softwareApi.reducerPath]: softwareApi.reducer,
    [devicesApi.reducerPath]: devicesApi.reducer,
    [cbomImportsApi.reducerPath]: cbomImportsApi.reducer,
    [syncLogsApi.reducerPath]: syncLogsApi.reducer,
    [schedulerApi.reducerPath]: schedulerApi.reducer,
    [policiesApi.reducerPath]: policiesApi.reducer,
    [trackingApi.reducerPath]: trackingApi.reducer,
    [xbomApi.reducerPath]: xbomApi.reducer,
    [cbomUploadsApi.reducerPath]: cbomUploadsApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware()
      .concat(integrationsApi.middleware)
      .concat(certificatesApi.middleware)
      .concat(endpointsApi.middleware)
      .concat(softwareApi.middleware)
      .concat(devicesApi.middleware)
      .concat(cbomImportsApi.middleware)
      .concat(syncLogsApi.middleware)
      .concat(schedulerApi.middleware)
      .concat(policiesApi.middleware)
      .concat(trackingApi.middleware)
      .concat(xbomApi.middleware)
      .concat(cbomUploadsApi.middleware),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
