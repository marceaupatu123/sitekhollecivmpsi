import * as pronote from "pawnote";

// Fonction pour extraire les arguments de la ligne de commande
const token = process.argv[2];

const session = pronote.createSessionHandle();
try {
  const SessionInfo = await pronote.loginToken(session, token);
  console.log("Logged in using token");
  return SessionInfo;
} catch (err) {
  if (/BadCredentialsError/.test(err.message)) {
    console.error(
      "BadCredentialsError: Unable to resolve the challenge, make sure the credentials or token are correct"
    );
    process.exit(2); // Code d'erreur spécial pour reconnexion
  } else {
    console.error("Erreur lors de la connexion avec le token", err);
    process.exit(1);
  }
}