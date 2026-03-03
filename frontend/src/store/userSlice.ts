/**
 * User slice — stores the current user selection in Redux + localStorage
 */
import { createSlice, PayloadAction } from '@reduxjs/toolkit';

const STORAGE_KEY = 'quantumguard-current-user-id';
const USERNAME_KEY = 'quantumguard-current-username';

interface UserState {
  currentUserId: string | null;
  currentUsername: string | null;
}

const initialState: UserState = {
  currentUserId: localStorage.getItem(STORAGE_KEY),
  currentUsername: localStorage.getItem(USERNAME_KEY),
};

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setCurrentUser(state, action: PayloadAction<{ id: string; username: string }>) {
      state.currentUserId = action.payload.id;
      state.currentUsername = action.payload.username;
      localStorage.setItem(STORAGE_KEY, action.payload.id);
      localStorage.setItem(USERNAME_KEY, action.payload.username);
    },
    clearCurrentUser(state) {
      state.currentUserId = null;
      state.currentUsername = null;
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem(USERNAME_KEY);
    },
  },
});

export const { setCurrentUser, clearCurrentUser } = userSlice.actions;
export default userSlice.reducer;
