// Provision the signing key automatically and keep it on a persistent volume (Node).
import { Daywalker } from "@shelbyb/daywalker-sdk";
import { fileKeyStore } from "@shelbyb/daywalker-sdk/keystore/file";

const client = new Daywalker({ keyStore: fileKeyStore({ path: process.env.DAYWALKER_KEY_FILE }) });
await client.provisionSigningKey(); // fail fast at startup
