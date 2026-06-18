/**
 * Shared scene configuration — pure data, no React.
 * Imported by frame-sequence, scene-overlay, scrolltimeline, and transition-effects.
 * Keeping this in a separate file avoids heavy cross-imports between "use client" components.
 */

export interface SceneConfig {
  id: number;
  name: string;
  frameCount: number;
  framePath: string;
}

export const SCENES: SceneConfig[] = [
  { id: 0, name: "Hero Intro", frameCount: 80, framePath: "/frames/scene1/frame_" },
  { id: 1, name: "Threat Intel", frameCount: 80, framePath: "/frames/scene2/frame_" },
  { id: 2, name: "AI Response", frameCount: 80, framePath: "/frames/scene3/frame_" },
  { id: 3, name: "Global Defense", frameCount: 80, framePath: "/frames/scene4/frame_" },
  { id: 4, name: "Command Center", frameCount: 80, framePath: "/frames/scene5/frame_" },
];

export const TOTAL_SCENES = SCENES.length;

/**
 * Scroll section heights (in vh) per scene.
 * Scene 02 (index 1) is taller to give the "2 robots on servers" frame
 * more screen time with its richer text overlay.
 */
export const SCENE_HEIGHTS_VH = [400, 650, 400, 400, 400];

export const TOTAL_HEIGHT_VH = SCENE_HEIGHTS_VH.reduce((a, b) => a + b, 0);

/** Compute cumulative scroll-progress boundaries for each scene. */
export function getSceneBoundaries(): { start: number; end: number }[] {
  let cum = 0;
  return SCENE_HEIGHTS_VH.map((h) => {
    const start = cum / TOTAL_HEIGHT_VH;
    cum += h;
    const end = cum / TOTAL_HEIGHT_VH;
    return { start, end };
  });
}

/** Pre-computed boundaries for hot-path usage */
export const SCENE_BOUNDARIES = getSceneBoundaries();
