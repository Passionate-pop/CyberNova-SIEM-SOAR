"use client";

import { useRef, useState, useCallback } from "react";
import dynamic from "next/dynamic";

/* ─── ALL heavy client components are lazy-loaded with ssr:false ─── */
const HeroSection = dynamic(() => import("@/components/hero"), { ssr: false });
const ScrollTimeline = dynamic(() => import("@/components/scrolltimeline"), { ssr: false });
const ScrollToTop = dynamic(() => import("@/components/scroll-to-top"), { ssr: false });
const KeyboardNav = dynamic(() => import("@/components/keyboard-nav"), { ssr: false });
const TransitionEffects = dynamic(() => import("@/components/transition-effects"), { ssr: false });
const ParticleFields = dynamic(() => import("@/components/particlefields"), { ssr: false });
const FrameSequence = dynamic(() => import("@/components/frame-sequence"), {
  ssr: false,
  loading: () => (
    <div className="fixed inset-0 bg-[#020B22] flex items-center justify-center">
      <div className="font-[family-name:var(--font-orbitron)] text-cyber-cyan/40 text-xs tracking-[0.3em] animate-pulse">
        INITIALIZING CYBERNOVA...
      </div>
    </div>
  ),
});
const SceneOverlays = dynamic(() => import("@/components/scene-overlay"), { ssr: false });

export default function Home() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [framesReady, setFramesReady] = useState(false);
  const handleReady = useCallback(() => setFramesReady(true), []);



  return (
    <main
      ref={containerRef}
      className="relative min-h-screen bg-[#020B22] overflow-x-hidden"
    >
      {/* ═══ Full-screen loading overlay — covers everything until frames load ═══ */}
      <div
        className="fixed inset-0 z-[100] bg-[#020B22] flex items-center justify-center transition-opacity duration-700 ease-out"
        style={{ opacity: framesReady ? 0 : 1, pointerEvents: framesReady ? "none" : "auto" }}
      >
        <div className="text-center">
          <div className="font-[family-name:var(--font-orbitron)] text-cyber-cyan/40 text-xs tracking-[0.3em] animate-pulse mb-5">
            INITIALIZING CYBERNOVA
          </div>
          <div className="w-48 mx-auto">
            <div className="h-[2px] w-full bg-cyber-deep/50 rounded-full overflow-hidden">
              <div className="h-full rounded-full animate-[loadingBar_3s_ease-in-out_infinite]" style={{ background: "linear-gradient(90deg, #69E5FF 0%, #9F63FF 50%, #FF4D9D 100%)" }} />
            </div>
          </div>
        </div>
      </div>


      {/* ═══ Layer 0: Multi-scene video frame sequence (scroll-driven) ═══ */}
      <div className="fixed inset-0 z-0">
        <FrameSequence onReady={handleReady} />
      </div>

      {/* ═══ Layer 1: Subtle particle overlay ═══ */}
      <div className="fixed inset-0 z-[1] pointer-events-none">
        <ParticleFields />
      </div>

      {/* ═══ Layer 2: Scanline overlay ═══ */}
      <div className="fixed inset-0 z-[2] scanline opacity-15 pointer-events-none" />

      {/* ═══ Layer 3: Hero Content (scene 1 only) ═══ */}
      <div className="fixed inset-0 z-[3]">
        <HeroSection />
      </div>

      {/* ═══ Layer 4: Scene text overlays (scenes 2–5) ═══ */}
      <div className="fixed inset-0 z-[4] pointer-events-none">
        <SceneOverlays />
      </div>

      {/* ═══ Layer 5: Cinematic transition effects ═══ */}
      <TransitionEffects />

      {/* ═══ Keyboard navigation ═══ */}
      <KeyboardNav />

      {/* ═══ Scroll to top button ═══ */}
      <ScrollToTop />

      {/* ═══ Scroll-driven timeline (controls scrollState) ═══ */}
      <ScrollTimeline />


    </main>
  );
}
