"use client";

import { useEffect } from "react";
import dynamicImport from "next/dynamic";
import { appConfig } from "@/lib/config";

export const dynamic = "force-static";

const ParticleFields = dynamicImport(() => import("@/components/particlefields"), {
  ssr: false,
});

export default function LoginPage() {
  // Auto-redirect on mount — real auth happens in the /app/ frontend
  useEffect(() => {
    const timer = setTimeout(() => {
      window.location.href = appConfig.loginUrl;
    }, 1500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="min-h-screen bg-[#020B22] relative overflow-x-hidden">

      {/* Particle background */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <ParticleFields />
      </div>

      {/* Scanline overlay */}
      <div className="fixed inset-0 z-[2] scanline opacity-15 pointer-events-none" />

      {/* Centered redirect card */}
      <div className="relative z-10 min-h-screen flex items-center justify-center px-4 pt-20 pb-12">
        <div className="w-full max-w-md text-center">
          {/* Header */}
          <div className="mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full border border-cyber-cyan/30 bg-cyber-cyan/10 mb-5 overflow-hidden">
              <img src="/logo.png" alt="CyberNova Logo" width={48} height={48} className="w-full h-full object-cover" />
            </div>
            <h1 className="font-[family-name:var(--font-orbitron)] text-2xl md:text-3xl font-extrabold uppercase tracking-wider mb-2" style={{ textShadow: "0 0 10px rgba(105,229,255,0.8), 0 0 30px rgba(105,229,255,0.6), 0 0 60px rgba(105,229,255,0.4), 0 0 100px rgba(105,229,255,0.2)" }}>
              Accessing CyberNova
            </h1>
            <p className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-[0.3em] text-cyber-purple uppercase font-extrabold">
              Redirecting to security dashboard
            </p>
          </div>

          {/* Redirect card */}
          <div className="neon-card rounded-2xl p-8 border border-cyber-cyan/15 glow-pulse">
            <div className="flex flex-col items-center gap-4">
              <div className="w-10 h-10 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
              <p className="text-sm text-cyber-white/50">
                Taking you to the CyberNova login page...
              </p>
              <a
                href={appConfig.loginUrl}
                className="mt-2 px-5 py-2 text-[0.65rem] font-[family-name:var(--font-orbitron)] tracking-[0.12em] uppercase text-cyber-cyan/90 bg-cyber-cyan/10 border border-cyber-cyan/30 hover:border-cyber-cyan/60 hover:bg-cyber-cyan/20 rounded-md transition-all duration-300"
              >
                Click here if not redirected
              </a>
            </div>
          </div>

          {/* Register link */}
          <p className="text-center mt-6 text-sm text-cyber-white/30">
            Don&apos;t have an account?{" "}
            <a href={appConfig.registerUrl} className="text-cyber-cyan/70 hover:text-cyber-cyan transition-colors duration-200 font-medium">
              Create Account
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
