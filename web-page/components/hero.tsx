"use client";

import { useRef, useEffect } from "react";
import gsap from "gsap";
import { onFrame } from "@/lib/animation-manager";

export default function HeroSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);
  const dividerRef = useRef<HTMLDivElement>(null);

  // Entrance animation (GSAP — runs once, no rAF needed)
  useEffect(() => {
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ delay: 0.2 });

      tl.fromTo(
        dividerRef.current,
        { scaleX: 0, opacity: 0 },
        { scaleX: 1, opacity: 1, duration: 0.5, ease: "power2.inOut" }
      )
        .fromTo(
          subtitleRef.current,
          { opacity: 0, y: 15 },
          { opacity: 1, y: 0, duration: 0.6, ease: "power3.out" },
          "-=0.3"
        );
    }, containerRef);
    return () => ctx.revert();
  }, []);

  // Scroll-driven fade — uses shared animation manager (no independent rAF)
  useEffect(() => {
    return onFrame((p) => {
      if (containerRef.current) {
        // Crossfade with scene 1: scene 1 fade-in starts at p=0.20
        // Hero stays visible until 0.08, then crossfades out by 0.20
        const fadeStart = 0.08;
        const fadeEnd = 0.20;
        const opacity =
          p <= fadeStart ? 1 : p >= fadeEnd ? 0 : 1 - (p - fadeStart) / (fadeEnd - fadeStart);
        const translateY = Math.min(p / fadeEnd, 1) * -60;
        containerRef.current.style.opacity = String(opacity);
        containerRef.current.style.transform = `translateY(${translateY}px)`;
        containerRef.current.style.pointerEvents = opacity < 0.05 ? "none" : "auto";
      }
    });
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative min-h-screen flex flex-col items-center justify-center px-4 sm:px-6 md:px-12 pt-16"
    >
      {/* Top brand */}

      {/* Center content */}
      <div className="relative z-10 text-center max-w-3xl mx-auto mt-16">
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
          24/7 autonomous security that monitors your servers, logs, network, and files.{" "}
          <span className="text-cyber-cyan font-semibold">
            Sees every threat. Filters the noise. Takes action in real time.
          </span>
        </p>

        <div className="mt-10 md:mt-12 flex items-center justify-center gap-8 opacity-0 animate-[fadeInUp_1s_1.4s_forwards]">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400" style={{ boxShadow: "0 0 6px rgba(74,222,128,0.6)" }} />
            <span className="font-inter text-[0.55rem] sm:text-[0.6rem] text-cyber-white/40 tracking-wider">
              99.97% Uptime
            </span>
          </div>
          <div className="w-[1px] h-3 bg-cyber-cyan/20" />
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-cyber-purple" style={{ boxShadow: "0 0 6px rgba(159,99,255,0.6)" }} />
            <span className="font-inter text-[0.55rem] sm:text-[0.6rem] text-cyber-white/40 tracking-wider">
              SOC-2 Compliant
            </span>
          </div>
          <div className="w-[1px] h-3 bg-cyber-cyan/20" />
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-cyber-magenta" style={{ boxShadow: "0 0 6px rgba(255,77,157,0.6)" }} />
            <span className="font-inter text-[0.55rem] sm:text-[0.6rem] text-cyber-white/40 tracking-wider">
              Sub-Second Response
            </span>
          </div>
        </div>

      </div>

      {/* Bottom scroll indicator */}
      <div className="absolute bottom-8 left-0 right-0 flex justify-center animate-bounce opacity-30">
        <svg width="20" height="30" viewBox="0 0 20 30" fill="none" className="text-cyber-cyan/50">
          <rect x="1" y="1" width="18" height="28" rx="9" stroke="currentColor" strokeWidth="1.5" />
          <circle cx="10" cy="10" r="2.5" fill="currentColor">
            <animate attributeName="cy" values="10;18;10" dur="1.5s" repeatCount="indefinite" />
          </circle>
        </svg>
      </div>

      {/* Side tech decorations */}
      <div className="hidden lg:block absolute left-8 top-1/2 -translate-y-1/2">
        <div className="flex flex-col items-center gap-3 opacity-20">
          <div className="w-[1px] h-16 bg-gradient-to-b from-transparent to-cyber-cyan/50" />
          <div className="w-1.5 h-1.5 rounded-full bg-cyber-cyan/50" />
          <div className="w-[1px] h-16 bg-gradient-to-b from-cyber-cyan/50 to-transparent" />
        </div>
      </div>
      <div className="hidden lg:block absolute right-8 top-1/2 -translate-y-1/2">
        <div className="flex flex-col items-center gap-3 opacity-20">
          <div className="w-[1px] h-16 bg-gradient-to-b from-transparent to-cyber-magenta/50" />
          <div className="w-1.5 h-1.5 rounded-full bg-cyber-magenta/50" />
          <div className="w-[1px] h-16 bg-gradient-to-b from-cyber-magenta/50 to-transparent" />
        </div>
      </div>
    </div>
  );
}
