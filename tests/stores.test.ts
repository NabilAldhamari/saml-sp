import { InMemoryReplayCache, InMemoryRequestStore } from "../src";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("InMemoryRequestStore", () => {
  it("consumes a stored ID exactly once", () => {
    const store = new InMemoryRequestStore();
    store.store("a");
    expect(store.consume("a")).toBe(true);
    expect(store.consume("a")).toBe(false);
  });

  it("returns false for unknown IDs", () => {
    const store = new InMemoryRequestStore();
    expect(store.consume("nope")).toBe(false);
  });

  it("expires entries after the TTL", async () => {
    const store = new InMemoryRequestStore(50);
    store.store("a");
    await sleep(200);
    expect(store.consume("a")).toBe(false);
  });

  it("sweeps expired entries from size", async () => {
    // Generous TTL so the pre-expiry assertion cannot flake on slow CI runners.
    const store = new InMemoryRequestStore(2_000);
    store.store("a");
    store.store("b");
    expect(store.size).toBe(2);

    const shortLived = new InMemoryRequestStore(50);
    shortLived.store("a");
    shortLived.store("b");
    await sleep(200);
    expect(shortLived.size).toBe(0);
  });

  it("evicts the oldest entry when maxEntries is reached", () => {
    const store = new InMemoryRequestStore(60_000, 2);
    store.store("a");
    store.store("b");
    store.store("c");
    expect(store.consume("a")).toBe(false);
    expect(store.consume("b")).toBe(true);
    expect(store.consume("c")).toBe(true);
  });
});

describe("InMemoryReplayCache", () => {
  const future = () => new Date(Date.now() + 60_000);

  it("registers a fresh ID and rejects a duplicate", () => {
    const cache = new InMemoryReplayCache();
    expect(cache.register("a", future())).toBe(true);
    expect(cache.register("a", future())).toBe(false);
  });

  it("allows re-registration after expiry", () => {
    const cache = new InMemoryReplayCache();
    expect(cache.register("a", new Date(Date.now() - 1000))).toBe(true);
    expect(cache.register("a", future())).toBe(true);
    expect(cache.register("a", future())).toBe(false);
  });

  it("sweeps expired entries when full", () => {
    const cache = new InMemoryReplayCache(2);
    cache.register("expired", new Date(Date.now() - 1000));
    cache.register("alive", future());
    cache.register("newcomer", future());
    expect(cache.size).toBeLessThanOrEqual(2);
    // The live entry must have survived the sweep.
    expect(cache.register("alive", future())).toBe(false);
  });

  it("evicts the oldest live entry when full of live entries", () => {
    const cache = new InMemoryReplayCache(2);
    cache.register("a", future());
    cache.register("b", future());
    cache.register("c", future());
    expect(cache.size).toBeLessThanOrEqual(2);
    expect(cache.register("a", future())).toBe(true); // evicted, so accepted again
  });
});
