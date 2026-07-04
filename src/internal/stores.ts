import type { ReplayCache, RequestStore } from "../types";

/**
 * Default in-memory store for outstanding AuthnRequest IDs.
 *
 * Suitable for single-process deployments. If you run multiple instances behind a
 * load balancer, provide a shared implementation (e.g. Redis-backed) instead —
 * the interface is two methods.
 */
export class InMemoryRequestStore implements RequestStore {
  /** id -> expiry epoch ms. Entries expire in insertion order (constant TTL). */
  private readonly entries = new Map<string, number>();

  constructor(
    private readonly ttlMs: number = 10 * 60_000,
    private readonly maxEntries: number = 10_000
  ) {}

  store(id: string): void {
    this.sweep();
    if (this.entries.size >= this.maxEntries) {
      // Evict the oldest outstanding request rather than grow without bound.
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(id, Date.now() + this.ttlMs);
  }

  consume(id: string): boolean {
    const expiresAt = this.entries.get(id);
    this.entries.delete(id);
    return expiresAt !== undefined && expiresAt > Date.now();
  }

  /** Number of currently outstanding (non-expired) request IDs. */
  get size(): number {
    this.sweep();
    return this.entries.size;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, expiresAt] of this.entries) {
      if (expiresAt > now) break; // constant TTL ⇒ insertion order == expiry order
      this.entries.delete(id);
    }
  }
}

/**
 * Default in-memory cache of consumed assertion IDs for replay detection.
 *
 * Suitable for single-process deployments; provide a shared implementation
 * (e.g. Redis SET NX with TTL) when running multiple instances.
 */
export class InMemoryReplayCache implements ReplayCache {
  /** id -> expiry epoch ms. */
  private readonly entries = new Map<string, number>();

  constructor(private readonly maxEntries: number = 50_000) {}

  register(id: string, expiresAt: Date): boolean {
    const now = Date.now();
    const existing = this.entries.get(id);
    if (existing !== undefined && existing > now) {
      return false; // replay
    }
    this.entries.delete(id);

    if (this.entries.size >= this.maxEntries) {
      this.sweep(now);
      if (this.entries.size >= this.maxEntries) {
        const oldest = this.entries.keys().next().value;
        if (oldest !== undefined) this.entries.delete(oldest);
      }
    }

    this.entries.set(id, expiresAt.getTime());
    return true;
  }

  /** Number of currently tracked assertion IDs (including not-yet-swept expired ones). */
  get size(): number {
    return this.entries.size;
  }

  private sweep(now: number): void {
    for (const [id, expiresAt] of this.entries) {
      if (expiresAt <= now) this.entries.delete(id);
    }
  }
}
