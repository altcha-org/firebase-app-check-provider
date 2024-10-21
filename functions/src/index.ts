import { webcrypto } from "node:crypto";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import * as https from "firebase-functions/v2/https";
import {applicationDefault, initializeApp} from "firebase-admin/app";
import {AppCheckToken} from "firebase-admin/app-check";
import {createChallenge, verifySolution} from "altcha-lib";

if (!('crypto' in globalThis)) {
  // @ts-ignore node typings error
  globalThis.crypto = webcrypto;
}

initializeApp({
  credential: applicationDefault(),
});

const hmacKey = process.env.HMAC_KEY || "";
const challengeTtlMinutes = parseInt(
  process.env.CHALLENGE_TTL_MINUTES || "10",
  10
);
const tokenTtlMinutes = parseInt(process.env.TOKEN_TTL_MINUTES || "30", 10);
const maxNumber = parseInt(process.env.MAX_NUMBER || "10000", 10);

exports.createAltchaChallenge = https.onRequest(
  {
    cors: true,
  },
  async (_request, response) => {
    try {
      const challengeResponse = await createChallenge({
        hmacKey,
        expires: new Date(Date.now() + 60000 * challengeTtlMinutes),
        maxNumber,
      });
      response.status(200).send(challengeResponse);
      return;
    } catch (error) {
      logger.error(error);
      throw new https.HttpsError(
        "internal",
        "Unable to generate ALTCHA challenge."
      );
    }
  }
);

exports.createAppCheckToken = https.onRequest(
  {
    cors: true,
  },
  async (request, response) => {
    const {appId, payload} = request.body as {
      appId: string;
      payload: string;
    };
    try {
      const isValid = await verifySolution(payload, hmacKey, true);
      if (isValid) {
        const appCheckToken: AppCheckToken = await admin
          .appCheck()
          .createToken(appId, {ttlMillis: 60000 * tokenTtlMinutes});
        response.status(200).send({
          token: appCheckToken.token,
          expireTimeMillis: Date.now() + appCheckToken.ttlMillis,
        });
        return;
      } else {
        throw new https.HttpsError(
          "permission-denied",
          "Invalid ALTCHA solution."
        );
      }
    } catch (error) {
      logger.error(error);
      throw new https.HttpsError(
        "permission-denied",
        "ALTCHA verification failed."
      );
    }
  }
);
