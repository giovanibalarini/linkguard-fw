import { createContext, useContext, useEffect, useState } from 'react';

/**
 * UIMode is the transversal "beginner vs power-user" axis of the UI.
 *
 * - "simple"   — fewer menu items (advanced ones tucked under a collapsible
 *                group), more guidance, task recipes up front. The default, so a
 *                first-time home user isn't overwhelmed.
 * - "advanced" — every screen visible at once, less hand-holding. One click in
 *                the sidebar flips to it and the choice is remembered.
 *
 * Nothing is ever truly hidden: simple mode only collapses the advanced group,
 * which the user can expand at any time. The mode just sets the default posture.
 */
export type UIMode = 'simple' | 'advanced';

const STORAGE_KEY = 'lg_ui_mode';

interface UIModeContextValue {
  mode: UIMode;
  isSimple: boolean;
  setMode: (m: UIMode) => void;
  toggle: () => void;
}

const UIModeContext = createContext<UIModeContextValue | undefined>(undefined);

function readStored(): UIMode {
  const v = localStorage.getItem(STORAGE_KEY);
  return v === 'advanced' ? 'advanced' : 'simple';
}

export function UIModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<UIMode>(readStored);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, mode);
  }, [mode]);

  const setMode = (m: UIMode) => setModeState(m);
  const toggle = () => setModeState((m) => (m === 'simple' ? 'advanced' : 'simple'));

  return (
    <UIModeContext.Provider value={{ mode, isSimple: mode === 'simple', setMode, toggle }}>
      {children}
    </UIModeContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useUIMode(): UIModeContextValue {
  const ctx = useContext(UIModeContext);
  if (!ctx) throw new Error('useUIMode must be used within UIModeProvider');
  return ctx;
}
