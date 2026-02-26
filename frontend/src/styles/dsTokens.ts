// ══════════════════════════════════════════════════════════════
//  DigiCert ONE — Design System Tokens (JS/TS)
//  Mirrors _variables.scss for use in TSX inline styles.
//  Keep in sync with _variables.scss.
// ══════════════════════════════════════════════════════════════

// ── Brand ───────────────────────────────────────────────────
export const DIGICERT_BLUE = '#0174C3';
export const DIGICERT_CYAN = '#20CCDE';

// ── Blue palette ────────────────────────────────────────────
export const BLUE_50  = '#EDF6FC';
export const BLUE_100 = '#94D2FC';
export const BLUE_200 = '#1297F3';
export const BLUE_300 = '#0174C3';
export const BLUE_400 = '#0165AC';
export const BLUE_500 = '#015A99';
export const BLUE_600 = '#004A80';
export const BLUE_700 = '#003E6B';
export const BLUE_800 = '#002947';
export const BLUE_900 = '#002036';

// ── Neutral palette ─────────────────────────────────────────
export const NEUTRAL_50  = '#F9FAFB';
export const NEUTRAL_100 = '#F0F3F5';
export const NEUTRAL_200 = '#E7EBEF';
export const NEUTRAL_300 = '#D6DCE1';
export const NEUTRAL_400 = '#C1C8CD';
export const NEUTRAL_500 = '#A0AAB0';
export const NEUTRAL_600 = '#757D82';
export const NEUTRAL_700 = '#636A6E';
export const NEUTRAL_800 = '#44484A';
export const NEUTRAL_900 = '#353535';

// ── Semantic colors ─────────────────────────────────────────
export const SUCCESS_50  = '#DEF8DE';
export const SUCCESS_100 = '#27A872';
export const SUCCESS_200 = '#1C7852';

export const ERROR_50  = '#FFE6E5';
export const ERROR_100 = '#DC2626';
export const ERROR_200 = '#AD0C0C';

export const WARNING_50  = '#FEEFCB';
export const WARNING_100 = '#F5B517';
export const WARNING_200 = '#955925';

export const INFO_50  = '#E2EEFF';
export const INFO_100 = '#0F73FF';
export const INFO_200 = '#0048AC';

// ── App-level semantic aliases ──────────────────────────────
export const DC1_TEXT          = NEUTRAL_900;   // #353535
export const DC1_TEXT_SECONDARY = NEUTRAL_700;  // #636A6E
export const DC1_TEXT_MUTED    = NEUTRAL_500;   // #A0AAB0
export const DC1_BORDER        = NEUTRAL_200;   // #E7EBEF
export const DC1_BG            = '#F5F6F8';
export const DC1_CARD          = '#FFFFFF';

export const DC1_SUCCESS = SUCCESS_100;  // #27A872
export const DC1_DANGER  = ERROR_100;    // #DC2626
export const DC1_WARNING = WARNING_100;  // #F5B517
export const DC1_INFO    = DIGICERT_BLUE; // #0174C3

// ── Chart palette ───────────────────────────────────────────
export const CHART_BLUE   = '#58a6ff';
export const CHART_PURPLE = '#bc8cff';
export const CHART_ORANGE = '#f0883e';
export const CHART_GREEN  = '#3fb950';
export const CHART_RED    = '#f85149';
export const CHART_YELLOW = '#d29922';
export const CHART_PINK   = '#f778ba';
export const CHART_CYAN   = DIGICERT_CYAN;
export const CHART_GRAY   = '#8b949e';

// ── Common tooltip style ────────────────────────────────────
export const TOOLTIP_STYLE = {
  backgroundColor: DC1_CARD,
  border: `1px solid ${DC1_BORDER}`,
  borderRadius: '8px',
  color: DC1_TEXT,
} as const;
