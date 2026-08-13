import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { en, type Dict } from "./messagesEn";
import { gu } from "./messagesGu";
import { hi } from "./messagesHi";

export type Language = "English" | "Hindi" | "Gujarati";

export const LANGUAGES: { id: Language; label: string; htmlLang: string }[] = [
  { id: "English", label: "English", htmlLang: "en" },
  { id: "Hindi", label: "हिन्दी", htmlLang: "hi" },
  { id: "Gujarati", label: "ગુજરાતી", htmlLang: "gu" },
];

const DICTS: Record<Language, Dict> = { English: en, Hindi: hi, Gujarati: gu };
const STORAGE_KEY = "netra.admin.language";

type LanguageValue = {
  language: Language;
  setLanguage: (next: Language) => void;
  t: (key: keyof Dict) => string;
};

const LanguageContext = createContext<LanguageValue | null>(null);

function initial(): Language {
  if (typeof window === "undefined") return "English";
  const stored = window.localStorage.getItem(STORAGE_KEY) as Language | null;
  return stored && stored in DICTS ? stored : "English";
}

/**
 * Language is a display preference, not a session secret, so it persists
 * across the memory-only administrative session — being asked to pick a
 * language again on every sign-in would be its own small insult.
 */
export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(initial);

  useEffect(() => {
    const entry = LANGUAGES.find((item) => item.id === language);
    // Screen readers switch voice on this, and it drives font selection for
    // Devanagari and Gujarati script.
    document.documentElement.lang = entry?.htmlLang ?? "en";
  }, [language]);

  const setLanguage = useCallback((next: Language) => {
    setLanguageState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // A console that cannot remember the choice must still honour it now.
    }
  }, []);

  const value = useMemo<LanguageValue>(() => {
    const dict = DICTS[language];
    return { language, setLanguage, t: (key) => dict[key] ?? en[key] };
  }, [language, setLanguage]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const value = useContext(LanguageContext);
  if (!value) throw new Error("useLanguage must be used inside LanguageProvider");
  return value;
}

/** Shorthand for the common case of only needing the lookup. */
export function useT() {
  return useLanguage().t;
}
