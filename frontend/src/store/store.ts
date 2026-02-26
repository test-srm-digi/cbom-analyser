/**
 * Redux Store — configured with RTK Query middleware
 */
import { configureStore } from '@reduxjs/toolkit';
import { integrationsApi } from './api/integrationsApi';

export const store = configureStore({
  reducer: {
    [integrationsApi.reducerPath]: integrationsApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(integrationsApi.middleware),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
