"use client";

import { useMemo } from "react";

interface Particle {
  id: number;
  x: number;
  y: number;
  size: number;
  duration: number;
  delay: number;
  opacity: number;
  color: string;
}

interface DustParticle {
  id: number;
  x: number;
  y: number;
  size: number;
  duration: number;
  delay: number;
  opacity: number;
}

interface StreamParticle {
  id: number;
  x: number;
  width: number;
  height: number;
  duration: number;
  delay: number;
  opacity: number;
  color: string;
}

/* ─────────────────── Floating Orbs ─────────────────── */
function FloatingOrbs() {
  const orbs = useMemo<Particle[]>(() => {
    return Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 6 + 2,
      duration: 8 + Math.random() * 12,
      delay: Math.random() * 5,
      opacity: Math.random() * 0.4 + 0.1,
      color:
        i % 3 === 0
          ? "rgba(105, 229, 255, VAR)"
          : i % 3 === 1
          ? "rgba(159, 99, 255, VAR)"
          : "rgba(0, 191, 255, VAR)",
    }));
  }, []);

  return (
    <div className="absolute inset-0 overflow-hidden">
      {orbs.map((orb) => (
        <div
          key={orb.id}
          className="absolute rounded-full"
          style={{
            left: `${orb.x}%`,
            top: `${orb.y}%`,
            width: `${orb.size}px`,
            height: `${orb.size}px`,
            background: orb.color.replace("VAR", String(orb.opacity)),
            boxShadow: `0 0 ${orb.size * 3}px ${orb.color.replace(
              "VAR",
              String(orb.opacity * 0.6)
            )}`,
            animation: `orbFloat ${orb.duration}s ${orb.delay}s ease-in-out infinite alternate`,
          }}
        />
      ))}
    </div>
  );
}

/* ─────────────────── Space Dust ─────────────────── */
function SpaceDust() {
  const dust = useMemo<DustParticle[]>(() => {
    return Array.from({ length: 50 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 1.8 + 0.8,
      duration: 15 + Math.random() * 20,
      delay: Math.random() * 8,
      opacity: Math.random() * 0.5 + 0.1,
    }));
  }, []);

  return (
    <div className="absolute inset-0 overflow-hidden">
      {dust.map((d) => (
        <div
          key={d.id}
          className="absolute rounded-full bg-cyber-cyan"
          style={{
            left: `${d.x}%`,
            top: `${d.y}%`,
            width: `${d.size}px`,
            height: `${d.size}px`,
            opacity: d.opacity,
            animation: `dustDrift ${d.duration}s ${d.delay}s linear infinite`,
          }}
        />
      ))}
    </div>
  );
}

/* ─────────────────── Data Streams ─────────────────── */
function DataStreams() {
  const streams = useMemo<StreamParticle[]>(() => {
    return Array.from({ length: 8 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      width: Math.random() * 1.5 + 0.5,
      height: Math.random() * 80 + 40,
      duration: 4 + Math.random() * 6,
      delay: Math.random() * 4,
      opacity: Math.random() * 0.15 + 0.05,
      color:
        i % 2 === 0
          ? "rgba(105, 229, 255, VAR)"
          : "rgba(159, 99, 255, VAR)",
    }));
  }, []);

  return (
    <div className="absolute inset-0 overflow-hidden">
      {streams.map((s) => (
        <div
          key={s.id}
          className="absolute"
          style={{
            left: `${s.x}%`,
            top: "-10%",
            width: `${s.width}px`,
            height: `${s.height}px`,
            background: `linear-gradient(180deg, transparent, ${s.color.replace(
              "VAR",
              String(s.opacity)
            )}, transparent)`,
            animation: `streamFall ${s.duration}s ${s.delay}s linear infinite`,
          }}
        />
      ))}
    </div>
  );
}

/* ─────────────────── Canvas wrapper ─────────────────── */
export default function ParticleFields() {
  return (
    <>
      <style>{`
        @keyframes orbFloat {
          0% { transform: translateY(0) translateX(0); }
          25% { transform: translateY(-30px) translateX(15px); }
          50% { transform: translateY(-10px) translateX(-20px); }
          75% { transform: translateY(-40px) translateX(10px); }
          100% { transform: translateY(-20px) translateX(-10px); }
        }
        @keyframes dustDrift {
          0% { transform: translateY(0) translateX(0); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(-100vh) translateX(30px); opacity: 0; }
        }
        @keyframes streamFall {
          0% { transform: translateY(-120%); }
          100% { transform: translateY(200vh); }
        }
      `}</style>
      <div className="absolute inset-0 pointer-events-none">
        <FloatingOrbs />
        <SpaceDust />
        <DataStreams />
      </div>
    </>
  );
}
