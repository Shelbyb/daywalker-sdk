import type { EvaluationContext, JsonValue, Logger as OFLogger, Provider, ResolutionDetails } from "@openfeature/web-sdk";
import { OpenFeatureEventEmitter, ProviderEvents } from "@openfeature/web-sdk";
import { createClient, type ClientOptions, type DevPulseClient } from "../flags/client.js";
import { toDevPulseContext, toResolution, typeCheck } from "./shared.js";

/**
 * OpenFeature provider for browsers, backed by @shelbyb/daywalker-sdk/flags. Flag
 * values update in real time and emit PROVIDER_CONFIGURATION_CHANGED.
 *
 *   await OpenFeature.setContext({ targetingKey: user.id });
 *   await OpenFeature.setProviderAndWait(new DevPulseWebProvider(clientSideId, { baseUrl }));
 */
export class DevPulseWebProvider implements Provider {
  readonly metadata = { name: "devpulse" } as const;
  readonly runsOn = "client" as const;
  readonly events = new OpenFeatureEventEmitter();
  private client: DevPulseClient | null = null;

  constructor(
    private readonly clientSideId: string,
    private readonly options: ClientOptions,
  ) {}

  async initialize(context?: EvaluationContext): Promise<void> {
    this.client = createClient(this.clientSideId, toDevPulseContext(context ?? {}) as never, { ...this.options, withReasons: true });
    this.client.on("change", (changes: unknown) => this.events.emit(ProviderEvents.ConfigurationChanged, { flagsChanged: Object.keys(changes as object) }));
    await this.client.waitForInitialization();
  }

  async onContextChange(_old: EvaluationContext, next: EvaluationContext): Promise<void> {
    await this.client?.identify(toDevPulseContext(next) as never);
  }

  async onClose(): Promise<void> {
    await this.client?.close();
  }

  private resolve<T>(key: string, def: T, type: string): ResolutionDetails<T> {
    if (!this.client) return toResolution({ value: def, variationIndex: null, reason: { kind: "ERROR", errorKind: "CLIENT_NOT_READY" } });
    return toResolution(typeCheck(this.client.variationDetail(key, def as never), type, def));
  }

  resolveBooleanEvaluation(key: string, def: boolean, _ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, "boolean");
  }
  resolveStringEvaluation(key: string, def: string, _ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, "string");
  }
  resolveNumberEvaluation(key: string, def: number, _ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, "number");
  }
  resolveObjectEvaluation<T extends JsonValue>(key: string, def: T, _ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, "object");
  }
}
