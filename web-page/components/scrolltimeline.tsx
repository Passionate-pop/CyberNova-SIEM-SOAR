"use client";

import { useRef, useEffect, useCallback } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { scrollState } from "@/lib/scrollstore";
import { SCENE_HEIGHTS_VH, TOTAL_HEIGHT_VH } from "@/lib/scene-config";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

interface TimelinePhase {
  label: string;
  name: string;
  events: string[];
}

const timelinePhases: TimelinePhase[] = [
  {
    label: "01",
    name: "Hero Intro",
    events: [
      "AI-powered SOC analyst revealed",
      "Thinks like a hacker",
      "Acts like a security chief",
    ],
  },
  {
    label: "02",
    name: "24/7 Monitoring",
    events: [
      "Server logs scanned in real time",
      "Network traffic monitored",
      "File integrity verified",
    ],
  },
  {
    label: "03",
    name: "Threat Detection",
    events: [
      "Threats identified instantly",
      "False alarms filtered out",
      "Auto-quarantine activated",
    ],
  },
  {
    label: "04",
    name: "Full Coverage",
    events: [
      "Every server protected",
      "Every endpoint covered",
      "Every asset secured",
    ],
  },
  {
    label: "05",
    name: "Autonomous Defense",
    events: [
      "Real-time response actions",
      "Zero human bottleneck",
      "Never sleeps, never stops",
    ],
  },
];



// Precompute cumulative boundaries for phase detection
const SCENE_BOUNDARIES = (() => {
  let cum = 0;
  return SCENE_HEIGHTS_VH.map((h) => {
    const start = cum / TOTAL_HEIGHT_VH;
    cum += h;
    return start;
  });
})();

export default function ScrollTimeline() {
  const containerRef = useRef<HTMLDivElement>(null);
  const progressFillRef = useRef<HTMLDivElement>(null);
  const phaseDotsRef = useRef<HTMLDivElement>(null);
  const activePhaseRef = useRef(0);

  const onScrollUpdate = useCallback((self: ScrollTrigger) => {
    const p = self.progress;
    scrollState.current = p;
    scrollState.target = p;

    // ─── Progress bar (direct DOM) ───
    if (progressFillRef.current) {
      progressFillRef.current.style.height = `${p * 100}%`;
    }
    // ─── Phase detection (variable heights) ───
    let phase = 0;
    for (let i = 0; i < timelinePhases.length; i++) {
      const boundary = (SCENE_HEIGHTS_VH.slice(0, i + 1).reduce((a, b) => a + b, 0)) / TOTAL_HEIGHT_VH;
      if (p >= boundary) phase = i;
    }

    // ─── Phase changed — update dots ───
    if (phase !== activePhaseRef.current) {
      activePhaseRef.current = phase;

      // Dots + labels
      if (phaseDotsRef.current) {
        const dots = phaseDotsRef.current.children;
        for (let i = 0; i < dots.length; i++) {
          const dot = dots[i] as HTMLElement;
          const dotCircle = dot.querySelector("div:first-child") as HTMLElement;
          const dotLabel = dot.querySelector("div:last-child") as HTMLElement;
          if (i <= phase) {
            dotCircle?.classList.add("border-cyber-cyan", "bg-cyber-cyan");
            dotCircle?.classList.remove("border-cyber-deep/60", "bg-transparent");
            dotCircle && (dotCircle.style.boxShadow = "0 0 10px rgba(105,229,255,0.6)");
          } else {
            dotCircle?.classList.remove("border-cyber-cyan", "bg-cyber-cyan");
            dotCircle?.classList.add("border-cyber-deep/60", "bg-transparent");
            dotCircle && (dotCircle.style.boxShadow = "none");
          }
          if (i === phase) {
            dotLabel?.classList.remove("opacity-0", "-translate-x-2");
            dotLabel?.classList.add("opacity-100", "translate-x-0");
          } else {
            dotLabel?.classList.add("opacity-0", "-translate-x-2");
            dotLabel?.classList.remove("opacity-100", "translate-x-0");
          }
        }
      }
    }
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const ctx = gsap.context(() => {
      ScrollTrigger.create({
        trigger: container,
        start: "top top",
        end: "bottom bottom",
        scrub: 0.2,
        onUpdate: onScrollUpdate,
      });
    }, container);

    return () => ctx.revert();
  }, [onScrollUpdate]);

  return (
    <>
    <div ref={containerRef} className="relative">
      {/* 5 snap-target sections, one per scene (variable heights for emphasis) */}
      {timelinePhases.map((_, i) => (
        <div
          key={i}
          style={{ height: `${SCENE_HEIGHTS_VH[i]}vh`, scrollSnapAlign: "start" }}
        />
      ))}
    </div>

      {/* Fixed timeline sidebar — persists across all snap sections */}
      <div className="fixed top-0 left-0 h-screen flex items-center pointer-events-none">
        {/* Left progress bar */}
        <div className="fixed left-2 sm:left-4 md:left-8 top-1/2 -translate-y-1/2 z-50 pointer-events-auto">
          <div className="relative flex flex-col items-center">
            {/* Progress track */}
            <div className="relative w-[2px] h-[280px] md:h-[360px] bg-cyber-deep/40 rounded-full overflow-hidden">
              <div
                ref={progressFillRef}
                className="absolute top-0 left-0 w-full rounded-full"
                style={{
                  height: "0%",
                  background:
                    "linear-gradient(180deg, #69E5FF 0%, #9F63FF 50%, #FF4D9D 100%)",
                  boxShadow: "0 0 12px rgba(105, 229, 255, 0.4)",
                }}
              />
            </div>

            {/* Phase dots */}
            <div ref={phaseDotsRef} className="absolute top-0 left-1/2 -translate-x-1/2 h-full flex flex-col justify-between py-0.5">
              {timelinePhases.map((phase, i) => (
                <div key={i} className="relative">
                  <div className="w-2.5 h-2.5 rounded-full border-2 border-cyber-deep/60 bg-transparent transition-all duration-500" />
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>
    </>
  );
}
