import { en } from "./ConsoleMessagesEn";
import { gu } from "./ConsoleMessagesGu";
import { hi } from "./ConsoleMessagesHi";
import { type Dict } from "./ConsoleCore";
import { type Language } from "../../lib/types";

export const translations: Record<Language, Dict> = { English: en, Hindi: hi, Gujarati: gu };
