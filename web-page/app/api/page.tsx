export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const endpoints = [
  { method: "GET", path: "/api/v1/threats", desc: "List all detected threats with filtering and pagination" },
  { method: "POST", path: "/api/v1/alerts", desc: "Create a custom alert rule with conditions and actions" },
  { method: "GET", path: "/api/v1/servers", desc: "List all monitored servers and their status" },
  { method: "PUT", path: "/api/v1/servers/:id/config", desc: "Update server monitoring configuration" },
  { method: "GET", path: "/api/v1/logs/search", desc: "Search through ingested logs with full-text query" },
  { method: "POST", path: "/api/v1/response/quarantine", desc: "Trigger manual quarantine on an endpoint" },
];

const methodColors: Record<string, string> = {
  GET: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30",
  POST: "text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/30",
  PUT: "text-amber-400 bg-amber-400/10 border-amber-400/30",
  DELETE: "text-red-400 bg-red-400/10 border-red-400/30",
};

export default function ApiPage() {
  return (
    <PageLayout title="API Reference" subtitle="Programmatic access to CyberNova's detection, monitoring, and response capabilities." accent="REST API v1">
      <div className="mb-8 neon-card p-4">
        <p className="text-sm text-cyber-white/60">
          Base URL: <code className="text-cyber-cyan font-mono">https://api.cybernova.io/v1</code>
        </p>
        <p className="text-xs text-cyber-white/40 mt-2">Authenticate with a Bearer token. Rate limited to 1000 req/min.</p>
      </div>
      <div className="space-y-3">
        {endpoints.map((ep, i) => (
          <div key={ep.path} className="neon-card p-4 card-enter flex flex-col sm:flex-row sm:items-center gap-3" style={{ animationDelay: `${i * 80}ms` }}>
            <span className={`inline-block px-2 py-0.5 rounded text-[0.6rem] font-[family-name:var(--font-orbitron)] font-bold tracking-wider border shrink-0 ${methodColors[ep.method] || "text-cyber-white/60"}`}>
              {ep.method}
            </span>
            <code className="font-mono text-sm text-cyber-cyan/80 shrink-0">{ep.path}</code>
            <span className="text-sm text-cyber-white/50 hidden md:inline">—</span>
            <span className="text-sm text-cyber-white/60">{ep.desc}</span>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
