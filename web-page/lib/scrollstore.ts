/**
 * Shared mutable scroll state.
 * GSAP ScrollTrigger writes to `current` from the DOM layer.
 * Frame sequence and scene overlays read from `current` in rAF loops.
 * This avoids any React re-render overhead between the two worlds.
 */
export const scrollState = {
  current: 0,
  target: 0,
};
