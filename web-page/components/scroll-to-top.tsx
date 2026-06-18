"use client";

import { useRef, useEffect } from "react";
import { onFrame } from "@/lib/animation-manager";

export default function ScrollToTop() {
  const btnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    return onFrame((p) => {
      if (btnRef.current) {
        const visible = p > 0.22;
        btnRef.current.style.opacity = visible ? "1" : "0";
        btnRef.current.style.transform = visible
          ? "translateY(0) scale(1)"
          : "translateY(12px) scale(0.8)";
        btnRef.current.style.pointerEvents = visible ? "auto" : "none";
      }
    });
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <button
      ref={btnRef}
      onClick={scrollToTop}
      aria-label="Scroll to top"
      className="fixed bottom-6 right-6 z-[55] w-10 h-10 md:w-11 md:h-11 rounded-full flex items-center justify-center opacity-0 transition-[box-shadow] duration-300 cursor-pointer group"
      style={{
        background: "rgba(4, 27, 82, 0.6)",
        backdropFilter: "blur(12px)",
        border: "1px solid rgba(105, 229, 255, 0.2)",
      }}
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="text-cyber-cyan/60 group-hover:text-cyber-cyan transition-colors duration-200"
      >
        <path d="M18 15l-6-6-6 6" />
      </svg>
      {/* Hover glow */}
      <div
        className="absolute inset-0 rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
        style={{
          boxShadow:
            "0 0 20px rgba(105, 229, 255, 0.35), inset 0 0 12px rgba(105, 229, 255, 0.08)",
        }}
      />
    </button>
  );
}
