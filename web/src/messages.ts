// The console's words for signing out, in English and Spanish. The console's
// foundations (plan P1-10.1) move every string to react-i18next.
const en = {
  signOut: "Sign out",
  signOutFailed: "Signing out failed. Try again.",
};

export type Messages = typeof en;

const es: Messages = {
  signOut: "Cerrar sesión",
  signOutFailed: "No se pudo cerrar la sesión. Inténtalo de nuevo.",
};

// messagesFor returns the words of the first of the browser's languages that
// the console speaks, or English.
export function messagesFor(languages: readonly string[]): Messages {
  for (const tag of languages) {
    const language = tag.toLowerCase().split("-")[0];
    if (language === "es") {
      return es;
    }
    if (language === "en") {
      return en;
    }
  }
  return en;
}
