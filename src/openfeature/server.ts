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
  /** Only a client this provider created is closed by onClose(); an injected one belongs to the caller. */
  private readonly ownsClient: boolean;
  private readonly detach: () => void;

  constructor(sdkKeyOrClient: string | DevPulseNodeClient, options?: NodeClientOptions) {
    this.ownsClient = typeof sdkKeyOrClient === "string";
    this.client = typeof sdkKeyOrClient === "string" ? init(sdkKeyOrClient, options!) : sdkKeyOrClient;
    const onUpdate = ({ key }: { key: string }) => this.events.emit(ProviderEvents.ConfigurationChanged, { flagsChanged: [key] });
    // Before initialization a failure rejects initialize() instead, which OpenFeature reports itself.
    const onFailed = (err?: Error) => this.client.isInitialized && this.events.emit(ProviderEvents.Error, { message: err?.message ?? "DevPulse client failed" });
    const onStale = (err?: Error) => this.events.emit(ProviderEvents.Stale, { message: err?.message ?? "DevPulse connection lost; serving last known flags" });
    const onRecovered = () => this.events.emit(ProviderEvents.Ready);
    this.client.on("update", onUpdate).on("failed", onFailed).on("stale", onStale).on("recovered", onRecovered);
    this.detach = () => void this.client.off("update", onUpdate).off("failed", onFailed).off("stale", onStale).off("recovered", onRecovered);
  }

  async initialize(): Promise<void> {
    await this.client.waitForInitialization();
  }

  async onClose(): Promise<void> {
    this.detach();
    if (this.ownsClient) await this.client.close();
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
