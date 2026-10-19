// Evaluate a flag locally with the pure engine (no network), e.g. in tests or a custom store.
import { evaluateFlag, MemoryStore, type FlagConfig } from "@shelbyb/daywalker-sdk/flags/engine";

const flag: FlagConfig = {
  key: "new-checkout",
  version: 1,
  on: true,
  salt: "new-checkout",
  variations: [false, true],
  offVariation: 0,
  fallthrough: { rollout: { variations: [{ variation: 0, weight: 50_000 }, { variation: 1, weight: 50_000 }] } },
  targets: [{ values: ["user-123"], variation: 1 }],
  rules: [],
  prerequisites: [],
};

const store = new MemoryStore({ flags: { [flag.key]: flag } });
const detail = evaluateFlag(store, "new-checkout", { kind: "user", key: "user-123" }, false);
console.log(detail.value, detail.reason);
