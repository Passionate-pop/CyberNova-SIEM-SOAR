"use client";

import { useRef, useEffect } from "react";
import gsap from "gsap";
import { onFrame } from "@/lib/animation-manager";
import { SCENES, SCENE_HEIGHTS_VH, TOTAL_SCENES, TOTAL_HEIGHT_VH, SCENE_BOUNDARIES } from "@/lib/scene-config";

/* ═══════════════════════════════════════════════════
   SCENE TEXT CONTENT
   ═══════════════════════════════════════════════════ */
export interface SceneContent {
  sceneIndex: number;
  label: string;
  tagline: string;
  headline: string;
  headlineAccent: string;
  description: string;
  features: string[];
}

export const SCENE_CONTENTS: SceneContent[] = [
  {
    sceneIndex: 1,
    label: "SCENE 02",
    tagline: "24/7 MONITORING",
    headline: "TWO SENTINELS,",
    headlineAccent: "NEVER BLINKING",
    description:
      "Two AI agents perched on their servers, scanning every log entry, every packet, every file change in real time. They monitor CPU loads, memory usage, network throughput, and disk I/O across your entire infrastructure. From unauthorized SSH attempts to suspicious cron jobs, every anomaly is detected, classified, and logged before you even finish your morning coffee.",
    features: ["Live Server Monitoring", "Log Stream Analysis", "File Integrity Checks", "Process Surveillance", "Network Traffic Analysis", "Real-Time Anomaly Detection"],
  },
  {
    sceneIndex: 2,
    label: "SCENE 03",
    tagline: "REAL-TIME THREAT DETECTION",
    headline: "SEES THE THREAT",
    headlineAccent: "FILTERS THE NOISE",
    description:
      "Thousands of alerts flood in daily. CyberNova's neural threat engine separates genuine attacks from benign anomalies — reducing noise by 94%. When a real threat emerges, it's flagged instantly with full context: attack vector, blast radius, and recommended response. No more alert fatigue. No more missed breaches.",
    features: ["Instant Threat Alerts", "Auto-Quarantine", "AI Noise Filtering", "Contextual Analysis"],
  },
  {
    sceneIndex: 3,
    label: "SCENE 04",
    tagline: "EVERY ASSET PROTECTED",
    headline: "YOUR ENTIRE",
    headlineAccent: "INFRASTRUCTURE COVERED",
    description:
      "From bare-metal servers to cloud instances, from database files to network endpoints — CyberNova deploys as your autonomous security agent across every asset. One dashboard. Full visibility. Zero blind spots across your entire attack surface.",
    features: ["Multi-Cloud Coverage", "Network Defense", "Database Protection", "Endpoint Security"],
  },
  {
    sceneIndex: 4,
    label: "SCENE 05",
    tagline: "AUTONOMOUS DEFENSE",
    headline: "ALWAYS ON",
    headlineAccent: "ALWAYS PROTECTING",
    description:
      "CyberNova never takes a break. It learns from every scan, adapts to new threat patterns instantly, and executes containment actions without waiting for human approval. Your infrastructure stays protected around the clock — so your security team can focus on strategy, not firefighting.",
    features: ["Real-Time Response", "Adaptive AI Learning", "Zero Downtime", "Auto-Containment"],
  },
];



/* ═══════════════════════════════════════════════════
   SINGLE OVERLAY — GSAP entrance + scroll-driven fade
   ═══════════════════════════════════════════════════ */
function SingleSceneOverlay({ content }: { content: SceneContent }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const taglineRef = useRef<HTMLParagraphElement>(null);
  const headlineRef = useRef<HTMLDivElement>(null);
  const dividerRef = useRef<HTMLDivElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);
  const featuresRef = useRef<HTMLDivElement>(null);
  const hasAnimatedRef = useRef(false);
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const sceneStart = SCENE_BOUNDARIES[content.sceneIndex].start;
    const sceneDuration = SCENE_BOUNDARIES[content.sceneIndex].end - SCENE_BOUNDARIES[content.sceneIndex].start;

    const onFrameCleanup = onFrame((p) => {
      const localP = Math.max(0, Math.min(1, (p - sceneStart) / sceneDuration));

      if (containerRef.current) {
        let opacity: number;
        // Fast fade-in (0–0.06), hold visible (0.06–0.72), late fade-out (0.72–0.90)
        if (localP <= 0.06) {
          opacity = localP / 0.06;
        } else if (localP <= 0.72) {
          opacity = 1;
        } else if (localP <= 0.90) {
          opacity = 1 - (localP - 0.72) / 0.18;
        } else {
          opacity = 0;
        }

        containerRef.current.style.opacity = String(opacity);
        containerRef.current.style.transform = `translateY(${(1 - opacity) * 30}px)`;
        containerRef.current.style.pointerEvents = opacity < 0.05 ? "none" : "auto";

        // ─── Trigger GSAP entrance animation once when scene becomes visible ───
        if (localP > 0.02 && !hasAnimatedRef.current) {
          hasAnimatedRef.current = true;
          cleanupRef.current?.();
          cleanupRef.current = playEntrance();
        }

        // ─── Reset when scene fades out so it can re-trigger next entry ───
        if (localP <= 0.01 && hasAnimatedRef.current) {
          hasAnimatedRef.current = false;
          cleanupRef.current?.();
          cleanupRef.current = null;
          resetElements();
        }
      }
    });

    return () => {
      onFrameCleanup();
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, [content.sceneIndex]);

  /* Build and play the staggered GSAP entrance timeline */
  const playEntrance = (): (() => void) => {
    const ctx = gsap.context(() => {
      const tl = gsap.timeline();

      tl.fromTo(
        taglineRef.current,
        { opacity: 0, y: 20, letterSpacing: "0.5em" },
        { opacity: 1, y: 0, letterSpacing: "0.3em", duration: 0.6, ease: "power3.out" }
      )
        .fromTo(
          headlineRef.current,
          { opacity: 0, y: 30 },
          { opacity: 1, y: 0, duration: 0.7, ease: "power3.out" },
          "-=0.3"
        )
        .fromTo(
          dividerRef.current,
          { scaleX: 0, opacity: 0 },
          { scaleX: 1, opacity: 1, duration: 0.5, ease: "power2.inOut" },
          "-=0.3"
        )
        .fromTo(
          subtitleRef.current,
          { opacity: 0, y: 15 },
          { opacity: 1, y: 0, duration: 0.6, ease: "power3.out" },
          "-=0.3"
        )
        .fromTo(
          featuresRef.current?.children
            ? Array.from(featuresRef.current.children)
            : [],
          { opacity: 0, y: 15, scale: 0.9 },
          {
            opacity: 1,
            y: 0,
            scale: 1,
            duration: 0.4,
            ease: "power3.out",
            stagger: 0.08,
          },
          "-=0.2"
        );
    });
    return () => ctx.revert();
  };

  /* Reset elements to hidden state for re-entry */
  const resetElements = () => {
    gsap.set(taglineRef.current, { opacity: 0, y: 20, letterSpacing: "0.5em" });
    gsap.set(headlineRef.current, { opacity: 0, y: 30 });
    gsap.set(dividerRef.current, { scaleX: 0, opacity: 0 });
    gsap.set(subtitleRef.current, { opacity: 0, y: 15 });
    if (featuresRef.current?.children) {
      gsap.set(Array.from(featuresRef.current.children), {
        opacity: 0,
        y: 15,
        scale: 0.9,
      });
    }
  };

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 flex items-center justify-center px-4 sm:px-6 md:px-12 opacity-0 scene-overlay"
    >
      <div className="relative z-10 text-center max-w-3xl mx-auto px-2">
        <p
          ref={taglineRef}
          className="font-[family-name:var(--font-orbitron)] text-[0.55rem] sm:text-[0.6rem] md:text-[0.75rem] tracking-[0.3em] sm:tracking-[0.4em] text-cyber-purple uppercase mb-4 md:mb-6 font-extrabold opacity-0"
        >
          {content.tagline}
        </p>
        <div ref={headlineRef} className="opacity-0">
          <h2 className="font-[family-name:var(--font-orbitron)] font-bold text-sm sm:text-lg md:text-2xl lg:text-3xl xl:text-4xl leading-[1.15] uppercase mb-2 md:mb-3">
            <span className="block text-cyber-white font-extrabold" style={{ textShadow: "0 0 10px rgba(105,229,255,0.8), 0 0 30px rgba(105,229,255,0.6), 0 0 60px rgba(105,229,255,0.4), 0 0 100px rgba(105,229,255,0.2)" }}>
              {content.headline}
            </span>
            <span className="block mt-1 text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-magenta font-extrabold" style={{ filter: "drop-shadow(0 0 8px rgba(105,229,255,0.5)) drop-shadow(0 0 20px rgba(159,99,255,0.4)) drop-shadow(0 0 40px rgba(255,77,157,0.3))" }}>
              {content.headlineAccent}
            </span>
          </h2>
        </div>
        <div className="flex justify-center my-3 md:my-5">
          <div
            ref={dividerRef}
            className="h-[1px] w-32 md:w-48 bg-gradient-to-r from-transparent via-cyber-cyan/50 to-transparent opacity-0"
          />
        </div>
        <p
          ref={subtitleRef}
          className="font-inter text-[0.65rem] sm:text-xs md:text-sm text-cyber-white/90 max-w-sm md:max-w-md mx-auto leading-relaxed opacity-0 font-semibold"
        >
          {content.description}
        </p>
        <div
          ref={featuresRef}
          className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 mt-5 md:mt-8 px-2"
        >
          {content.features.map((feat, i) => (
            <span
              key={i}
              className="glass-strong rounded-full px-3 md:px-4 py-1 md:py-1.5 font-[family-name:var(--font-orbitron)] text-[0.5rem] sm:text-[0.6rem] md:text-[0.65rem] tracking-wider font-bold text-cyber-cyan border border-cyber-cyan/30 opacity-0"
            >
              {feat}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════
   MAIN EXPORT
   ═══════════════════════════════════════════════════ */
export default function SceneOverlays() {
  return (
    <>
      {SCENE_CONTENTS.map((content) => (
        <SingleSceneOverlay key={content.sceneIndex} content={content} />
      ))}
    </>
  );
}
