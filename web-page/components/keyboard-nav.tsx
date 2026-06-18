"use client";

import { useEffect } from "react";
import { scrollState } from "@/lib/scrollstore";

const TOTAL_SCENES = 5;

/**
 * Keyboard navigation: Arrow Up/Down or Page Up/Down to jump between scenes.
 * Jumps to the nearest scene boundary based on current scroll position.
 */
export default function KeyboardNav() {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isNavKey =
        e.key === "ArrowDown" ||
        e.key === "ArrowUp" ||
        e.key === "PageDown" ||
        e.key === "PageUp" ||
        e.key === "Home" ||
        e.key === "End";

      if (!isNavKey) return;

      // Don't intercept if user is focused on an input/textarea
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

      e.preventDefault();

      const p = scrollState.current;
      const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;

      let targetP: number;

      switch (e.key) {
        case "ArrowDown":
        case "PageDown":
          targetP = Math.min(
            Math.ceil(p * TOTAL_SCENES + 0.01) / TOTAL_SCENES,
            1
          );
          break;
        case "ArrowUp":
        case "PageUp":
          targetP = Math.max(
            Math.floor(p * TOTAL_SCENES - 0.01) / TOTAL_SCENES,
            0
          );
          break;
        case "Home":
          targetP = 0;
          break;
        case "End":
          targetP = 1;
          break;
        default:
          return;
      }

      window.scrollTo({ top: targetP * scrollHeight, behavior: "smooth" });
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return null;
}
