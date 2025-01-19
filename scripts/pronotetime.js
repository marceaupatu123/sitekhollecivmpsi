import * as pronote from "pawnote";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import { Storage } from "@google-cloud/storage";
import ical from "ical-generator";
import path from "path";

// Déterminer si nous sommes en local ou non
const IS_LOCAL = true;

async function main() {
  // Extraire les arguments de la ligne de commande
  const jsonstring = process.argv[2];
  if (!jsonstring) {
    console.error("Erreur: l'argument token est requis");
    process.exit(1);
  }
  const userId = process.argv[3];
  if (!userId) {
    console.error("Erreur: l'argument user_id est requis");
    process.exit(1);
  }

  // Décoder le token
  const token = JSON.parse(jsonstring);

  const session = pronote.createSessionHandle();

  try {
    // Connexion
    const SessionInfo = await pronote.loginToken(session, {
      url: "https://0061642c.index-education.net/pronote/eleve.html?login=true",
      navigatorIdentifier: token.navigatorIdentifier,
      kind: token.kind,
      username: token.username,
      token: token.token,
      deviceUUID: "123e4567-e89b-12d3-a456-426614174000",
    });
    SessionInfo.navigatorIdentifier =
      SessionInfo.navigatorIdentifier || token.navigatorIdentifier;
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
    console.log(sessionInfoJson);
    const now = new Date();
    const endOfMonth = new Date(now);
    endOfMonth.setMonth(now.getMonth() + 1);

    // Récupérer l'emploi du temps
    const timetable = await pronote.timetableFromIntervals(
      session,
      now,
      endOfMonth
    );
    const events = timetable.classes.map((lesson) => ({
      start: lesson.startDate.toISOString(),
      end: lesson.endDate.toISOString(),
      title:
        lesson.is === "activity"
          ? `ACTIVITY: ${lesson.title}`
          : lesson.is === "detention"
          ? `DETENTION: ${lesson.title}`
          : lesson.is === "lesson"
          ? `${lesson.subject?.name || "(unknown subject)"}`
          : "UNKNOWN",
      type: lesson.is,
      room: lesson.classrooms[0],
      teacher: lesson.teacherNames[0],
      color: lesson.backgroundColor,
    }));

    // Générer un nom de fichier unique
    const uniqueId = uuidv4();
    const jsonFilePath = path.join(`/tmp/timetable_${uniqueId}.json`);
    const icsFilePath = path.join(`/tmp/timetable_${uniqueId}.ics`);

    // Écrire le fichier JSON
    fs.writeFileSync(jsonFilePath, JSON.stringify(events, null, 2));

    // Créer un fichier iCalendar
    const cal = ical({ name: "Emploi du temps" });
    events.forEach((event) => {
      cal.createEvent({
        start: new Date(event.start),
        end: new Date(event.end),
        summary: event.title,
        location: event.room,
        organizer: { 
          name: event.teacher || 'N/A'
        },
        description: `Prof: ${event.teacher || 'N/A'}`,
        "X-COLOR": event.color,
      });
    });

    // Écrire le fichier iCalendar
    const icalString = cal.toString();
    fs.writeFileSync(icsFilePath, icalString);

    // Initialiser le client de stockage
    let storage;
    if (IS_LOCAL) {
      storage = new Storage({ keyFilename: "./jsonid.json" });
    } else {
      storage = new Storage();
    }

    const bucketName = "sacred-ember-377216.appspot.com";
    const destinationBlobName = `Calendriers/${userId}.ics`;

    // Télécharger le fichier .ics dans le bucket de stockage cloud
    await storage.bucket(bucketName).upload(icsFilePath, {
      destination: destinationBlobName,
    });

    // Supprimer les fichiers locaux
    fs.unlinkSync(jsonFilePath);
    fs.unlinkSync(icsFilePath);
  } catch (err) {
    if (err.message.includes("BadCredentialsError")) {
      console.error(
        "BadCredentialsError: Unable to resolve the challenge, make sure the credentials or token are correct"
      );
      process.exit(2);
    } else {
      console.error(
        "Erreur lors de la connexion ou de l'exportation de l'emploi du temps",
        err
      );
      process.exit(1);
    }
  }
}

// Appeler la fonction principale
main();
