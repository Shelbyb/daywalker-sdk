/** A tiny EventEmitter subset (no node:events) so the server client runs on Deno, Bun and Workers. */
type Listener = (...args: any[]) => void;

export class Emitter {
  private listeners = new Map<string, Listener[]>();

  on(event: string, listener: Listener): this {
    const list = this.listeners.get(event);
    if (list) list.push(listener);
    else this.listeners.set(event, [listener]);
    return this;
  }
  addListener(event: string, listener: Listener): this {
    return this.on(event, listener);
  }
  once(event: string, listener: Listener): this {
    const wrapper: Listener & { listener?: Listener } = (...args) => {
      this.off(event, wrapper);
      listener(...args);
    };
    wrapper.listener = listener;
    return this.on(event, wrapper);
  }
  off(event: string, listener: Listener): this {
    const list = this.listeners.get(event);
    if (!list) return this;
    const i = list.findIndex((l) => l === listener || (l as { listener?: Listener }).listener === listener);
    if (i >= 0) list.splice(i, 1);
    if (!list.length) this.listeners.delete(event);
    return this;
  }
  removeListener(event: string, listener: Listener): this {
    return this.off(event, listener);
  }
  removeAllListeners(event?: string): this {
    if (event === undefined) this.listeners.clear();
    else this.listeners.delete(event);
    return this;
  }
  listenerCount(event: string): number {
    return this.listeners.get(event)?.length ?? 0;
  }
  emit(event: string, ...args: unknown[]): boolean {
    const list = this.listeners.get(event);
    if (!list?.length) return false;
    for (const l of [...list]) l(...args);
    return true;
  }
}
