"use client";

import { useRef, useEffect, useMemo } from "react";
import { onFrame } from "@/lib/animation-manager";

/** Deterministic pseudo-random: same seed → same value on server & client */
function seededRandom(seed: number): number {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return x - Math.floor(x);
}

const TOTAL_SCENES = 5;
const CROSSFADE_RATIO = 0.2;

/* ═══════════════════════════════════════════════════
   FLOATING PARTICLES — burst outward during transitions
   ═══════════════════════════════════════════════════ */
interface TransitionParticle {
  id: number;
  angle: number;
  distance: number;
  size: number;
  color: string;
  speed: number;
}

function TransitionParticles({ intensityRef }: { intensityRef: React.RefObject<number> }) {
  const containerRef = useRef<HTMLDivElement>(null);

  const particles = useMemo<TransitionParticle[]>(() => {
    return Array.from({ length: 24 }, (_, i) => {
      const angle = (i / 24) * Math.PI * 2 + (seededRandom(i * 7 + 301) - 0.5) * 0.5;
      const colors = [
        "rgba(105, 229, 255, VAR)",
        "rgba(159, 99, 255, VAR)",
        "rgba(255, 77, 157, VAR)",
        "rgba(0, 191, 255, VAR)",
      ];
      return {
        id: i,
        angle,
        distance: 30 + seededRandom(i * 13 + 302) * 70,
        size: 1 + seededRandom(i * 19 + 303) * 3,
        color: colors[i % colors.length],
        speed: 0.5 + seededRandom(i * 23 + 304) * 0.5,
      };
    });
  }, []);

  useEffect(() => {
    return onFrame(() => {
      if (!containerRef.current) return;
      const intensity = intensityRef.current;
      if (intensity < 0.01) {
        containerRef.current.style.opacity = "0";
        return;
      }
      containerRef.current.style.opacity = String(intensity);

      const children = containerRef.current.children;
      for (let i = 0; i < children.length && i < particles.length; i++) {
        const el = children[i] as HTMLElement;
        const p = particles[i];
        const dist = p.distance * intensity * p.speed;
        const x = Math.cos(p.angle) * dist;
        const y = Math.sin(p.angle) * dist;
        const opacity = Math.min(intensity * 2, 0.8);
        const scale = 0.3 + intensity * 0.7;
        el.style.transform = `translate(${x}px, ${y}px) scale(${scale})`;
        el.style.opacity = String(opacity);
      }
    });
  }, [particles, intensityRef]);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 flex items-center justify-center pointer-events-none"
      style={{ opacity: 0 }}
    >
      {particles.map((p) => (
        <div
          key={p.id}
          className="absolute rounded-full"
          style={{
            width: `${p.size}px`,
            height: `${p.size}px`,
            background: p.color.replace("VAR", "0.8"),
            boxShadow: `0 0 ${p.size * 4}px ${p.color.replace("VAR", "0.5")}`,
          }}
        />
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════
   GLITCH FLASH — horizontal displacement + color shift
   ═══════════════════════════════════════════════════ */
function GlitchFlash({ intensityRef }: { intensityRef: React.RefObject<number> }) {
  const containerRef = useRef<HTMLDivElement>(null);
  // Stable position for the flash line — determined once at mount
  const flashLineTop = useMemo(() => 30 + seededRandom(501) * 40, []);

  useEffect(() => {
    return onFrame(() => {
      if (!containerRef.current) return;
      const intensity = intensityRef.current;
      if (intensity < 0.01) {
        containerRef.current.style.opacity = "0";
        return;
      }
      containerRef.current.style.opacity = String(intensity * 0.7);

      // Horizontal scanline displacement
      const offset = Math.sin(Date.now() * 0.02) * intensity * 8;
      containerRef.current.style.transform = `translateX(${offset}px)`;
    });
  }, [intensityRef]);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 pointer-events-none transition-glitch"
      style={{ opacity: 0 }}
    >
      {/* Cyan color channel shift */}
      <div
        className="absolute inset-0 mix-blend-screen"
        style={{
          background: "linear-gradient(180deg, transparent 40%, rgba(105, 229, 255, 0.03) 50%, transparent 60%)",
          animation: "glitchScan 0.15s linear",
        }}
      />
      {/* Magenta horizontal lines */}
      <div
        className="absolute inset-0"
        style={{
          background: `repeating-linear-gradient(
            0deg,
            transparent,
            transparent 4px,
            rgba(255, 77, 157, 0.02) 4px,
            rgba(255, 77, 157, 0.02) 5px
          )`,
        }}
      />
      {/* Stable white flash line */}
      <div
        className="absolute left-0 right-0 h-[1px]"
        style={{
          top: `${flashLineTop}%`,
          background: "rgba(247, 251, 255, 0.15)",
          boxShadow: "0 0 20px rgba(105, 229, 255, 0.3)",
        }}
      />
    </div>
  );
}

/* ═══════════════════════════════════════════════════
   VIGNETTE PULSE — darkens edges during transitions
   ═══════════════════════════════════════════════════ */
function VignettePulse({ intensityRef }: { intensityRef: React.RefObject<number> }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    return onFrame(() => {
      if (!containerRef.current) return;
      const intensity = intensityRef.current;
      if (intensity < 0.01) {
        containerRef.current.style.opacity = "0";
        return;
      }
      const spread = 40 + intensity * 20;
      containerRef.current.style.opacity = String(intensity * 0.8);
      containerRef.current.style.background = `radial-gradient(ellipse at center, transparent ${spread}%, rgba(2, 11, 34, 0.6) 100%)`;
    });
  }, [intensityRef]);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 pointer-events-none"
      style={{ opacity: 0 }}
    />
  );
}

/* ═══════════════════════════════════════════════════
   MAIN EXPORT
   ═══════════════════════════════════════════════════ */
export default function TransitionEffects() {
  const intensityRef = useRef(0);

  useEffect(() => {
    return onFrame((p) => {
      const sceneDuration = 1 / TOTAL_SCENES;
      const crossfadeHalf = (sceneDuration * CROSSFADE_RATIO) / 2;

      let maxIntensity = 0;
      // Check each scene boundary
      for (let i = 1; i < TOTAL_SCENES; i++) {
        const boundary = i * sceneDuration;
        const dist = Math.abs(p - boundary);
        if (dist < crossfadeHalf) {
          // Bell curve: peaks at center of crossfade zone
          const normalized = 1 - dist / crossfadeHalf;
          const intensity = normalized * normalized; // quadratic ease
          if (intensity > maxIntensity) maxIntensity = intensity;
        }
      }
      intensityRef.current = maxIntensity;
    });
  }, []);

  return (
    <>
      <style>{`
        @keyframes glitchScan {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100%); }
        }
        .transition-glitch {
          mix-blend-mode: screen;
        }
      `}</style>
      <div className="fixed inset-0 z-[5] pointer-events-none">
        <VignettePulse intensityRef={intensityRef} />
        <TransitionParticles intensityRef={intensityRef} />
        <GlitchFlash intensityRef={intensityRef} />
      </div>
    </>
  );
}
