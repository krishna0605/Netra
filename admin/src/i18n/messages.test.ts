import { describe, expect, it } from "vitest";

import { en } from "./messagesEn";
import { gu } from "./messagesGu";
import { hi } from "./messagesHi";

/**
 * A missing or malformed string in a console like this can sit directly next
 * to a destructive button, so the dictionaries are checked rather than
 * trusted.
 */

const LANGUAGES = { Hindi: hi, Gujarati: gu };
const keys = Object.keys(en) as (keyof typeof en)[];

describe("dictionaries", () => {
  it("cover every key", () => {
    for (const [name, dict] of Object.entries(LANGUAGES)) {
      const missing = keys.filter((key) => !(key in dict));
      expect(missing, `${name} is missing keys`).toEqual([]);
    }
  });

  it("never render a raw identifier", () => {
    // Spreading English first means an untranslated key falls back to readable
    // text. This proves that fallback holds rather than assuming it.
    for (const [name, dict] of Object.entries(LANGUAGES)) {
      for (const key of keys) {
        const value = dict[key];
        expect(typeof value, `${name}.${String(key)}`).toBe("string");
        expect(value.length, `${name}.${String(key)} is empty`).toBeGreaterThan(0);
        expect(value, `${name}.${String(key)} looks like a key`).not.toBe(String(key));
      }
    }
  });

  it("translate the security-critical consequence lines out of English", () => {
    // These are the sentences that decide whether someone hesitates before
    // stripping a second factor. Falling back to English here would be a
    // silent failure — the dialog would still look complete.
    const critical = [
      "confirmResetAuth1",
      "confirmResetAuth2",
      "confirmResetAuth3",
      "confirmDeactivate1",
      "confirmDeactivate2",
      "confirmDeactivate3",
      "confirmRevokeAll1",
      "confirmRevokeAll2",
      "confirmRevokeAll3",
      "transferConsequence1",
      "transferConsequence2",
      "transferConsequence3",
      "handoverWarning",
      "endEverySessionHint",
    ] as const;

    for (const [name, dict] of Object.entries(LANGUAGES)) {
      for (const key of critical) {
        expect(dict[key], `${name}.${key} still reads as English`).not.toBe(en[key]);
      }
    }
  });

  it("keeps every key translated, not only the critical ones", () => {
    for (const [name, dict] of Object.entries(LANGUAGES)) {
      const untranslated = keys.filter((key) => dict[key] === en[key]);
      // A handful of proper nouns and abbreviations legitimately match.
      expect(untranslated.length, `${name} has ${untranslated.length} untranslated keys: ${untranslated.join(", ")}`).toBeLessThan(6);
    }
  });
});
