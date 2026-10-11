import type { EvaluationContext, JsonValue, Logger as OFLogger, Provider, ResolutionDetails } from "@openfeature/server-sdk";
import { OpenFeatureEventEmitter, ProviderEvents } from "@openfeature/server-sdk";
import { init, type DevPulseNodeClient, type NodeClientOptions } from "../flags/node.js";
import { toDevPulseContext, toResolution, typeCheck } from "./shared.js";

/**
 * OpenFeature provider for servers, backed by @shelbyb/daywalker-sdk/flags/node (local evaluation,
 * real-time updates).
 *
 *   await OpenFeature.setProviderAndWait(new DevPulseServerProvider(sdkKey, { baseUrl }));
 *   const enabled = await OpenFeature.getClient().getBooleanValue("new-checkout", false, { targetingKey: user.id });
 */
export class DevPulseServerProvider implements Provider {
  readonly metadata = { name: "devpulse" } as const;
  readonly runsOn = "server" as const;
  readonly events = new OpenFeatureEventEmitter();
  readonly client: DevPulseNodeClient;

  constructor(sdkKeyOrClient: string | DevPulseNodeClient, options?: NodeClientOptions) {
    this.client = typeof sdkKeyOrClient === "string" ? init(sdkKeyOrClient, options!) : sdkKeyOrClient;
    this.client.on("update", ({ key }: { key: string }) => this.events.emit(ProviderEvents.ConfigurationChanged, { flagsChanged: [key] }));
  }

  async initialize(): Promise<void> {
    await this.client.waitForInitialization();
  }

  async onClose(): Promise<void> {
    await this.client.close();
  }

  private resolve<T>(key: string, def: T, ctx: EvaluationContext, type: string): ResolutionDetails<T> {
    const detail = this.client.variationDetailSync(key, toDevPulseContext(ctx), def as never);
    return toResolution(typeCheck(detail, type, def));
  }

  async resolveBooleanEvaluation(key: string, def: boolean, ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, ctx, "boolean");
  }
  async resolveStringEvaluation(key: string, def: string, ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, ctx, "string");
  }
  async resolveNumberEvaluation(key: string, def: number, ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, ctx, "number");
  }
  async resolveObjectEvaluation<T extends JsonValue>(key: string, def: T, ctx: EvaluationContext, _logger: OFLogger) {
    return this.resolve(key, def, ctx, "object");
  }
}
