/**
 * Single shared requestAnimationFrame loop for all scroll-driven animations.
 * Components register callbacks; one rAF loop drives them all.
 * This eliminates 7+ concurrent rAF loops that were running independently.
 */

type TickCallback = (progress: number) => void;

const callbacks: Set<TickCallback> = new Set();
let rafId = 0;
let running = false;

/** Import the shared scroll state directly to avoid circular deps */
let scrollProgress = 0;
export function setScrollProgress(p: number) {
  scrollProgress = p;
}

function tick() {
  const p = scrollProgress;
  for (const cb of callbacks) {
    cb(p);
  }
  rafId = requestAnimationFrame(tick);
}

/** Register a callback to be called every frame with the current scroll progress. */
export function onFrame(cb: TickCallback): () => void {
  callbacks.add(cb);
  if (!running) {
    running = true;
    rafId = requestAnimationFrame(tick);
  }
  return () => {
    callbacks.delete(cb);
    if (callbacks.size === 0 && running) {
      running = false;
      cancelAnimationFrame(rafId);
    }
  };
}
