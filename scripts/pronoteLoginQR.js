import * as pronote from "pawnote";
import fs from "fs";
import { promisify } from "util";

const writeFile = promisify(fs.writeFile);

void (async function loginWithQR() {
  const session = pronote.createSessionHandle();
  const qrContent = process.argv[2];
  try {
    const jsonObject = JSON.parse(qrContent);
    const SessionInfo = await pronote.loginQrCode(session, {
      pin: "0000",
      deviceUUID: "123e4567-e89b-12d3-a456-426614174000",
      qr: jsonObject,
    });
    
    const profilePictureUrl = encodeURIComponent(session.user.resources[0].profilePicture.url);
    SessionInfo["profile_picture"] = profilePictureUrl;
    
    const sessionInfoJson = JSON.stringify(
      SessionInfo,
      (key, value) => {
        if (typeof value === "string" && value.startsWith("http")) {
          return encodeURIComponent(value);
        }
        return value;
      },
      2
    );
    
    console.log(sessionInfoJson); // Utilisez console.log pour retourner la sortie
  } catch (err) {
    console.error("Erreur lors de la connexion avec QR code", err);
    process.exit(1);
  }
})();
