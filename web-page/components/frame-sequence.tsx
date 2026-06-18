"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import { scrollState } from "@/lib/scrollstore";
import { onFrame, setScrollProgress } from "@/lib/animation-manager";
import {
  SCENES,
  TOTAL_SCENES,
  SCENE_HEIGHTS_VH,
  SCENE_BOUNDARIES,
  type SceneConfig,
} from "@/lib/scene-config";

/* Re-export for backward compatibility */
export type { SceneConfig };
export { SCENES, SCENE_HEIGHTS_VH };

/* ═══════════════════════════════════════════════════
   CROSSFADE CONFIGURATION
   ═══════════════════════════════════════════════════ */
const CROSSFADE_RATIO = 0.2;

/* ═══════════════════════════════════════════════════
   CINEMATIC EFFECT CONSTANTS
   - Outgoing scene zooms from 1.0 → OUTGOING_MAX_SCALE as it fades out
   - Incoming scene settles from INCOMING_START_SCALE → 1.0 as it fades in
   - Outgoing scene drifts upward by PARALLAX_DRIFT pixels during crossfade
   - Static scenes get a slow Ken Burns zoom for visual life
   ═══════════════════════════════════════════════════ */
const OUTGOING_MAX_SCALE = 1.08;
const INCOMING_START_SCALE = 1.03;
const PARALLAX_DRIFT = -0.02; // fraction of canvas height (upward)
const KENBURNS_SCALE = 1.04; // total zoom over full scene duration

/* ═══════════════════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════════════════ */
function getFrameSrc(scene: SceneConfig, frameIndex: number): string {
  return `${scene.framePath}${String(frameIndex + 1).padStart(4, "0")}.webp`;
}

interface CrossfadeResult {
  fromScene: number;
  fromFrame: number;
  toScene: number;
  toFrame: number;
  alpha: number; // 0 = fully "from", 1 = fully "to"
}

/**
 * Given global scroll progress p ∈ [0, 1], compute which scene(s) to draw
 * and the crossfade alpha between them.
 */
function resolveCrossfade(p: number): CrossfadeResult {
  const crossfadeFrames = CROSSFADE_RATIO / 2;

  // Use variable scene boundaries for crossfade zones
  for (let i = 0; i < TOTAL_SCENES - 1; i++) {
    const boundary = SCENE_BOUNDARIES[i + 1].start;
    const fromWidth = SCENE_BOUNDARIES[i].end - SCENE_BOUNDARIES[i].start;
    const toWidth = SCENE_BOUNDARIES[i + 1].end - SCENE_BOUNDARIES[i + 1].start;
    const avgWidth = (fromWidth + toWidth) / 2;
    const zoneHalf = (avgWidth * CROSSFADE_RATIO) / 2;
    const zoneStart = boundary - zoneHalf;
    const zoneEnd = boundary + zoneHalf;

    if (p >= zoneStart && p <= zoneEnd) {
      const alpha = Math.min(Math.max((p - zoneStart) / (zoneEnd - zoneStart), 0), 1);

      const fromScene = SCENES[i];
      const fromLocalP = (1 - crossfadeFrames) + alpha * crossfadeFrames;
      const fromFrame = Math.min(
        Math.floor(fromLocalP * fromScene.frameCount),
        fromScene.frameCount - 1
      );

      const toScene = SCENES[i + 1];
      const toLocalP = alpha * crossfadeFrames;
      const toFrame = Math.min(
        Math.floor(toLocalP * toScene.frameCount),
        toScene.frameCount - 1
      );

      return { fromScene: i, fromFrame, toScene: i + 1, toFrame, alpha };
    }
  }

  // Find which scene we're in using variable boundaries
  let sceneIndex = 0;
  for (let i = 0; i < TOTAL_SCENES; i++) {
    if (p >= SCENE_BOUNDARIES[i].start && p < SCENE_BOUNDARIES[i].end) {
      sceneIndex = i;
      break;
    }
    sceneIndex = i;
  }

  const sceneWidth = SCENE_BOUNDARIES[sceneIndex].end - SCENE_BOUNDARIES[sceneIndex].start;
  const localP = Math.min((p - SCENE_BOUNDARIES[sceneIndex].start) / sceneWidth, 1);
  const scene = SCENES[sceneIndex];
  const frameIndex = Math.min(
    Math.floor(localP * scene.frameCount),
    scene.frameCount - 1
  );

  return {
    fromScene: sceneIndex,
    fromFrame: frameIndex,
    toScene: sceneIndex,
    toFrame: frameIndex,
    alpha: 1,
  };
}

/**
 * Draw a frame with cinematic transform applied.
 * Uses canvas save/restore with scale + translate for zoom and parallax.
 */
function drawFrame(
  ctx: CanvasRenderingContext2D,
  img: HTMLImageElement,
  canvasW: number,
  canvasH: number,
  scale: number,
  translateYFraction: number,
  alpha: number
) {
  ctx.save();
  ctx.globalAlpha = alpha;
  // Use canvas transforms for zoom + parallax — cleaner and no gap artifacts.
  // Canvas clips overflow automatically, so zoomed edges are handled.
  ctx.translate(canvasW / 2, canvasH / 2);
  ctx.scale(scale, scale);
  ctx.translate(-canvasW / 2, -canvasH / 2 + canvasH * translateYFraction);
  ctx.drawImage(img, 0, 0, canvasW, canvasH);
  ctx.restore();
}

/* ═══════════════════════════════════════════════════
   COMPONENT
   ═══════════════════════════════════════════════════ */
interface FrameSequenceProps {
  onReady?: () => void;
}

export default function FrameSequence({ onReady }: FrameSequenceProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sceneFramesRef = useRef<(HTMLImageElement[] | null)[]>(
    Array.from({ length: TOTAL_SCENES }, () => null)
  );
  const loadedScenesRef = useRef<Set<number>>(new Set());
  const [overallProgress, setOverallProgress] = useState(0);
  const [isReady, setIsReady] = useState(false);
  const lastDrawnRef = useRef<{
    fromScene: number;
    fromFrame: number;
    toScene: number;
    toFrame: number;
    alpha: number;
  }>({ fromScene: -1, fromFrame: -1, toScene: -1, toFrame: -1, alpha: -1 });
  const lastImgRef = useRef<HTMLImageElement | null>(null);

  /* ─── Load a single scene's frames ─── */
  const loadScene = useCallback((sceneIndex: number) => {
    if (loadedScenesRef.current.has(sceneIndex)) return;
    if (sceneFramesRef.current[sceneIndex]) return;

    const scene = SCENES[sceneIndex];
    const frames: HTMLImageElement[] = new Array(scene.frameCount);
    let loaded = 0;

    for (let i = 0; i < scene.frameCount; i++) {
      const img = new Image();
      img.src = getFrameSrc(scene, i);
      img.onload = () => {
        loaded++;
        if (loaded === scene.frameCount) {
          loadedScenesRef.current.add(sceneIndex);
          const totalLoaded = loadedScenesRef.current.size;
          setOverallProgress(Math.round((totalLoaded / TOTAL_SCENES) * 100));
          if (totalLoaded === TOTAL_SCENES || sceneIndex === 0) {
            setIsReady(true);
            onReady?.();
          }
        }
      };
      frames[i] = img;
    }

    sceneFramesRef.current[sceneIndex] = frames;
  }, []);

  /* ─── Load scene 1 immediately, rest lazily ─── */
  useEffect(() => {
    loadScene(0);
  }, [loadScene]);

  useEffect(() => {
    return onFrame((p) => {
      for (let i = 1; i < TOTAL_SCENES; i++) {
        if (p >= SCENE_BOUNDARIES[i].start - 0.05) {
          loadScene(i);
        }
      }
    });
  }, [loadScene]);

  /* ─── Canvas resize handling ─── */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const syncSize = () => {
      const container = canvas.parentElement;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
    };

    syncSize();

    const ro = new ResizeObserver(syncSize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);
    window.addEventListener("resize", syncSize);

    return () => {
      ro.disconnect();
      window.removeEventListener("resize", syncSize);
    };
  }, []);

  /* ─── Render via shared animation manager (single rAF loop) ─── */
  useEffect(() => {
    if (!isReady) return;

    return onFrame((p) => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const { fromScene, fromFrame, toScene, toFrame, alpha } = resolveCrossfade(p);

      // Skip redraw if nothing changed
      if (
        fromScene === lastDrawnRef.current.fromScene &&
        fromFrame === lastDrawnRef.current.fromFrame &&
        toScene === lastDrawnRef.current.toScene &&
        toFrame === lastDrawnRef.current.toFrame &&
        alpha === lastDrawnRef.current.alpha
      )
        return;

      const fromFrames = sceneFramesRef.current[fromScene];
      const fromImg = fromFrames?.[fromFrame];
      const toFrames = sceneFramesRef.current[toScene];
      const toImg = toFrames?.[toFrame];

      const refImg = alpha >= 0.5 ? (toImg || fromImg) : (fromImg || toImg);
      if (!refImg || !refImg.complete || !refImg.naturalWidth) return;

      // Size canvas to match frame resolution
      if (canvas.width !== refImg.naturalWidth || canvas.height !== refImg.naturalHeight) {
        canvas.width = refImg.naturalWidth;
        canvas.height = refImg.naturalHeight;
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = "high";
      }

      lastDrawnRef.current = { fromScene, fromFrame, toScene, toFrame, alpha };
      lastImgRef.current = refImg;

      const cw = canvas.width;
      const ch = canvas.height;
      const inTransition = fromScene !== toScene;

      if (inTransition) {
        /* ─── Cinematic crossfade ─── */
        // Outgoing: zooms in + drifts upward as it fades out
        if (fromImg && fromImg.complete && fromImg.naturalWidth > 0) {
          const outScale = 1 + alpha * (OUTGOING_MAX_SCALE - 1);
          const outDrift = alpha * PARALLAX_DRIFT;
          drawFrame(ctx, fromImg, cw, ch, outScale, outDrift, 1 - alpha);
        }

        // Incoming: settles from zoomed-in to 1.0 as it fades in
        if (toImg && toImg.complete && toImg.naturalWidth > 0) {
          const inScale = INCOMING_START_SCALE - alpha * (INCOMING_START_SCALE - 1);
          drawFrame(ctx, toImg, cw, ch, inScale, 0, alpha);
        }
      } else {
        /* ─── Ken Burns: subtle slow zoom on static scenes ─── */
        let kbSceneIndex = 0;
        for (let i = 0; i < TOTAL_SCENES; i++) {
          if (p >= SCENE_BOUNDARIES[i].start && p < SCENE_BOUNDARIES[i].end) {
            kbSceneIndex = i;
            break;
          }
          kbSceneIndex = i;
        }
        const kbSceneWidth = SCENE_BOUNDARIES[kbSceneIndex].end - SCENE_BOUNDARIES[kbSceneIndex].start;
        const localP = Math.min((p - SCENE_BOUNDARIES[kbSceneIndex].start) / kbSceneWidth, 1);
        const kbScale = 1 + localP * (KENBURNS_SCALE - 1);

        if (toImg && toImg.complete && toImg.naturalWidth > 0) {
          drawFrame(ctx, toImg, cw, ch, kbScale, 0, 1);
        } else if (lastImgRef.current?.complete) {
          drawFrame(ctx, lastImgRef.current, cw, ch, kbScale, 0, 1);
        }
      }
    });
  }, [isReady]);

  /* ─── Sync scroll state into animation manager ─── */
  useEffect(() => {
    return onFrame(() => {
      setScrollProgress(scrollState.current);
    });
  }, []);

  return (
    <div className="fixed inset-0 z-0 overflow-hidden">
      <canvas ref={canvasRef} className="w-full h-full object-cover" style={{ transform: "scale(1.02)" }} />

      {!isReady && (
        <div className="absolute inset-0 flex items-center justify-center bg-[#020B22] z-10">
          <div className="text-center">
            <div className="font-[family-name:var(--font-orbitron)] text-cyber-cyan/40 text-xs tracking-[0.3em] animate-pulse mb-5">
              INITIALIZING CYBERNOVA
            </div>
            <div className="w-56 mx-auto mb-3">
              <div className="h-[2px] w-full bg-cyber-deep/50 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300 ease-out"
                  style={{
                    width: `${overallProgress}%`,
                    background: "linear-gradient(90deg, #69E5FF 0%, #9F63FF 50%, #FF4D9D 100%)",
                    boxShadow: "0 0 12px rgba(105, 229, 255, 0.5)",
                  }}
                />
              </div>
            </div>
            <div className="font-[family-name:var(--font-orbitron)] text-cyber-cyan/30 text-[0.6rem] tracking-[0.25em]">
              {overallProgress}% — LOADING FRAMES
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
