"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const pageNames: Record<string, string> = {
  features: "Features",
  platform: "Platform",
  pricing: "Pricing",
  changelog: "Changelog",
  docs: "Documentation",
  api: "API Reference",
  blog: "Blog",
  status: "System Status",
  about: "About",
  careers: "Careers",
  contact: "Contact",
  security: "Security",
};

export default function Breadcrumb() {
  const pathname = usePathname();
  const segments = pathname.split("/").filter(Boolean);
  const currentPage = segments[segments.length - 1] || "";
  const pageName = pageNames[currentPage] || currentPage;

  return (
    <nav aria-label="Breadcrumb" className="flex items-center justify-center gap-3 mb-4">
      {/* Back to Home */}
      <Link
        href="/"
        className="group inline-flex items-center gap-2 font-[family-name:var(--font-orbitron)] text-[0.55rem] sm:text-[0.6rem] tracking-[0.15em] text-cyber-white/40 hover:text-cyber-cyan uppercase transition-all duration-300"
      >
        <span className="inline-flex items-center justify-center w-5 h-5 rounded border border-cyber-cyan/15 bg-cyber-cyan/5 group-hover:border-cyber-cyan/40 group-hover:bg-cyber-cyan/10 transition-all duration-300">
          <svg
            width="10"
            height="10"
            viewBox="0 0 12 12"
            fill="none"
            className="text-cyber-cyan/50 group-hover:text-cyber-cyan transition-colors duration-300 -translate-x-[0.5px]"
          >
            <path
              d="M7.5 2.5L4 6l3.5 3.5"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        <span className="group-hover:-translate-x-0.5 transition-transform duration-300">Home</span>
      </Link>

      {pageName && (
        <>
          <span className="text-cyber-cyan/20 text-[0.5rem]">▸</span>
          <span
            className="font-[family-name:var(--font-orbitron)] text-[0.55rem] sm:text-[0.6rem] tracking-[0.2em] text-cyber-cyan uppercase"
            style={{ textShadow: "0 0 8px rgba(105,229,255,0.6)" }}
          >
            {pageName}
          </span>
        </>
      )}
    </nav>
  );
}
