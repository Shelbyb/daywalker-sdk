// In-memory key store for tests, and the read-only env key store.
import { Daywalker } from "@shelbyb/daywalker-sdk";
import { envKeyStore, memoryKeyStore } from "@shelbyb/daywalker-sdk/keystore";

export const testClient = new Daywalker({ keyStore: memoryKeyStore() });
export const envClient = new Daywalker({ keyStore: envKeyStore() });
