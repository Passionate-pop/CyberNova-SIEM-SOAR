"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { appConfig } from "@/lib/config";

const navLinks = [
  { label: "Features", href: "/features" },
  { label: "Platform", href: "/platform" },
  { label: "Pricing", href: "/pricing" },
  { label: "Docs", href: "/docs" },
];

export default function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();

  const isActive = (href: string) => pathname === href;

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-[60]"
      style={{ background: "transparent", backdropFilter: "none", borderBottom: "1px solid transparent" }}
    >
      <div className="w-full px-4 sm:px-6 lg:px-8">
        <div className="relative flex items-center justify-between h-16 md:h-18">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <div className="relative">
              <div className="w-9 h-9 rounded-full overflow-hidden border border-cyber-cyan/40 group-hover:border-cyber-cyan/70 transition-all duration-300">
                <img src="/logo.png" alt="CyberNova Logo" width={36} height={36} className="w-full h-full object-cover" />
              </div>
              <div className="absolute -inset-1 rounded-full bg-cyber-cyan/10 blur-md opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            </div>
            <span className="font-[family-name:var(--font-orbitron)] text-sm font-bold tracking-[0.2em] text-cyber-white/90 uppercase">
              CyberNova
            </span>
          </Link>

          {/* Centered nav links */}
          <div className="hidden md:flex items-center gap-1 absolute left-1/2 -translate-x-1/2">
            {navLinks.map((link) => (
              <Link
                key={link.label}
                href={link.href}
                className={`relative px-4 py-2 text-[0.7rem] font-[family-name:var(--font-orbitron)] tracking-[0.15em] uppercase transition-colors duration-300 group ${
                  isActive(link.href)
                    ? "text-cyber-cyan"
                    : "text-cyber-white/70 hover:text-cyber-cyan"
                }`}
                style={
                  isActive(link.href)
                    ? { textShadow: "0 0 12px rgba(105,229,255,0.8), 0 0 30px rgba(105,229,255,0.4)" }
                    : undefined
                }
              >
                {link.label}
                <span
                  className={`absolute bottom-0 left-1/2 -translate-x-1/2 h-[1px] bg-cyber-cyan/60 transition-all duration-300 ${
                    isActive(link.href) ? "w-3/4" : "w-0 group-hover:w-3/4"
                  }`}
                  style={
                    isActive(link.href)
                      ? { boxShadow: "0 0 8px rgba(105,229,255,0.6)" }
                      : undefined
                  }
                />
              </Link>
            ))}
          </div>

          {/* Auth button — right side */}
          <div className="hidden md:flex items-center gap-2">
            <a
              href={appConfig.loginUrl}
              className="px-5 py-1.5 text-[0.65rem] font-[family-name:var(--font-orbitron)] tracking-[0.12em] uppercase text-cyber-cyan/90 bg-cyber-cyan/10 border border-cyber-cyan/30 hover:border-cyber-cyan/60 hover:bg-cyber-cyan/20 rounded-md transition-all duration-300"
              style={{ boxShadow: "0 0 12px rgba(105,229,255,0.08)" }}
            >
              Get Started
            </a>
          </div>

          {/* Mobile hamburger */}
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden relative w-8 h-8 flex flex-col items-center justify-center gap-1.5 group"
            aria-label="Toggle menu"
          >
            <span
              className={`w-5 h-[1.5px] bg-cyber-cyan/70 transition-all duration-300 ${
                mobileOpen ? "translate-y-[4.5px] rotate-45" : ""
              }`}
            />
            <span
              className={`w-5 h-[1.5px] bg-cyber-cyan/70 transition-all duration-300 ${
                mobileOpen ? "opacity-0 scale-0" : ""
              }`}
            />
            <span
              className={`w-5 h-[1.5px] bg-cyber-cyan/70 transition-all duration-300 ${
                mobileOpen ? "-translate-y-[4.5px] -rotate-45" : ""
              }`}
            />
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      <div
        className={`md:hidden overflow-hidden transition-all duration-300 ${
          mobileOpen ? "max-h-80 opacity-100" : "max-h-0 opacity-0"
        }`}
        style={{
          background: "rgba(2, 11, 34, 0.95)",
          backdropFilter: "blur(20px)",
          borderTop: mobileOpen ? "1px solid rgba(105, 229, 255, 0.1)" : "none",
        }}
      >
        <div className="px-4 py-4 space-y-1">
          {navLinks.map((link) => (
            <Link
              key={link.label}
              href={link.href}
              onClick={() => setMobileOpen(false)}
              className={`block px-4 py-3 text-[0.7rem] font-[family-name:var(--font-orbitron)] tracking-[0.15em] uppercase rounded-lg transition-all duration-200 ${
                isActive(link.href)
                  ? "text-cyber-cyan bg-cyber-cyan/10"
                  : "text-cyber-white/70 hover:text-cyber-cyan hover:bg-cyber-cyan/5"
              }`}
              style={
                isActive(link.href)
                  ? { textShadow: "0 0 12px rgba(105,229,255,0.8)" }
                  : undefined
              }
            >
              {link.label}
            </Link>
          ))}

          {/* Mobile auth button */}
          <div className="pt-3 mt-2 border-t border-cyber-cyan/10">
            <a
              href={appConfig.loginUrl}
              onClick={() => setMobileOpen(false)}
              className="block text-center px-4 py-2.5 text-[0.65rem] font-[family-name:var(--font-orbitron)] tracking-[0.12em] uppercase text-cyber-cyan/90 bg-cyber-cyan/10 border border-cyber-cyan/30 hover:border-cyber-cyan/60 hover:bg-cyber-cyan/20 rounded-md transition-all duration-300"
            >
              Get Started
            </a>
          </div>
        </div>
      </div>
    </nav>
  );
}
