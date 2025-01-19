import fs from "fs";
import { promisify } from "util";
import { execSync } from "child_process";

const readFile = promisify(fs.readFile);
let SessionInfo;

// Vérifier si un argument est passé
const arg = process.argv[2];

if (arg) {
  if (arg.startsWith("qr=")) {
    const qrContent = arg.slice(3);
    try {
      const scriptPath = './scripts/pronoteLoginQR.js';
      const output = execSync(`node "${scriptPath}" ${qrContent}`, { encoding: 'utf8' });
      if (output) {
        SessionInfo = JSON.parse(output);
        console.log(SessionInfo);
      } else {
        console.error('Erreur: La sortie du script est vide.');
      }
    } catch (err) {
      console.error("Erreur lors de la connexion avec QR code", err);
      process.exit(1);
    }
  } else if (arg.startsWith("token=")) {
    try {
      const token = arg.slice(6); // Extraire le token de l'argument
      const scriptPath = './scripts/pronoteLoginToken.js';
      execSync(`node "${scriptPath}" ${token}`, { encoding: 'utf8' }); // Passer le token au script
      if (output) {
        SessionInfo = JSON.parse(output);
        console.log("Logged in using token");
        console.log(SessionInfo);
      } else {
        console.error('Erreur: La sortie du script est vide.');
      }
    } catch (err) {
      console.error("Erreur lors de la connexion avec le token", err);
      process.exit(1);
    }
  } else {
    console.error("Argument non reconnu. Utilisez 'qr=' ou 'token='.");
    process.exit(1);
  }
} else {
  console.error("Aucun argument fourni.");
  process.exit(1);
}