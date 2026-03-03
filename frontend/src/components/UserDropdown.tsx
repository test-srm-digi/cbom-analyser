/**
 * UserDropdown — topbar component for selecting / creating users
 */
import { useState, useRef, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useGetUsersQuery, useCreateUserMutation } from '../store/api/usersApi';
import { setCurrentUser, clearCurrentUser } from '../store/userSlice';
import type { RootState } from '../store/store';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUser, faPlus, faChevronDown, faCheck } from '@fortawesome/pro-light-svg-icons';
import './UserDropdown.scss';

export default function UserDropdown() {
  const dispatch = useDispatch();
  const { currentUserId, currentUsername } = useSelector(
    (state: RootState) => state.user,
  );
  const { data: users = [] } = useGetUsersQuery();
  const [createUser] = useCreateUserMutation();

  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
        setCreating(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleSelect = (id: string, username: string) => {
    dispatch(setCurrentUser({ id, username }));
    setOpen(false);
    // Reload page to re-fetch all data with new userId header
    window.location.reload();
  };

  const handleCreate = async () => {
    const trimmed = newName.trim();
    if (!trimmed) return;
    try {
      const user = await createUser({ username: trimmed }).unwrap();
      dispatch(setCurrentUser({ id: user.id, username: user.username }));
      setNewName('');
      setCreating(false);
      setOpen(false);
      window.location.reload();
    } catch (err) {
      console.error('Failed to create user:', err);
    }
  };

  return (
    <div className={`user-dropdown ${open ? 'user-dropdown--open' : ''}`} ref={ref}>
      <button
        className="user-dropdown__trigger"
        onClick={() => setOpen(!open)}
        type="button"
      >
        <FontAwesomeIcon icon={faUser} />
        <span className="user-dropdown__name">
          {currentUsername || 'Select User'}
        </span>
        <FontAwesomeIcon icon={faChevronDown} className="user-dropdown__caret" />
      </button>

      {open && (
        <div className="user-dropdown__menu">
          <div className="user-dropdown__header">Switch User</div>

          <div className="user-dropdown__list">
            {users.map((u) => (
              <button
                key={u.id}
                className={`user-dropdown__item ${u.id === currentUserId ? 'user-dropdown__item--active' : ''}`}
                onClick={() => handleSelect(u.id, u.username)}
                type="button"
              >
                <span>{u.username}</span>
                {u.id === currentUserId && (
                  <FontAwesomeIcon icon={faCheck} className="user-dropdown__check" />
                )}
              </button>
            ))}
          </div>

          <div className="user-dropdown__divider" />

          {creating ? (
            <div className="user-dropdown__create-form">
              <input
                className="user-dropdown__input"
                type="text"
                placeholder="Enter username..."
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                autoFocus
              />
              <button
                className="user-dropdown__create-btn"
                onClick={handleCreate}
                type="button"
              >
                Add
              </button>
            </div>
          ) : (
            <button
              className="user-dropdown__item user-dropdown__item--new"
              onClick={() => setCreating(true)}
              type="button"
            >
              <FontAwesomeIcon icon={faPlus} />
              <span>Create New User</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}
