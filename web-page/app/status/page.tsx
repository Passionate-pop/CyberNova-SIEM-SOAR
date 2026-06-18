export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const services = [
  { name: "API Gateway", status: "operational", uptime: "99.99%" },
  { name: "Threat Detection Engine", status: "operational", uptime: "99.98%" },
  { name: "Log Ingestion Pipeline", status: "operational", uptime: "99.99%" },
  { name: "Auto-Quarantine Service", status: "operational", uptime: "99.97%" },
  { name: "Dashboard & Web UI", status: "operational", uptime: "100%" },
  { name: "Alert Notification System", status: "operational", uptime: "99.99%" },
  { name: "ML Model Training Cluster", status: "maintenance", uptime: "99.90%" },
];

const statusColors: Record<string, string> = {
  operational: "bg-emerald-400",
  degraded: "bg-amber-400",
  maintenance: "bg-cyan-400",
  outage: "bg-red-400",
};

const statusLabels: Record<string, string> = {
  operational: "Operational",
  degraded: "Degraded",
  maintenance: "Maintenance",
  outage: "Outage",
};

export default function StatusPage() {
  return (
    <PageLayout title="System Status" subtitle="Real-time health monitoring of all CyberNova infrastructure and services." accent="Uptime Dashboard">
      <div className="neon-card p-6 mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-emerald-400 uppercase tracking-wider">All Systems Operational</span>
        </div>
        <p className="text-sm text-cyber-white/50">Last updated: {new Date().toLocaleString()}</p>
      </div>
      <div className="space-y-3">
        {services.map((s, i) => (
          <div key={s.name} className="neon-card p-4 card-enter flex flex-col sm:flex-row sm:items-center justify-between gap-3" style={{ animationDelay: `${i * 0.08}s` }}>
            <div className="flex items-center gap-3">
              <div className={`w-2.5 h-2.5 rounded-full ${statusColors[s.status]} ${s.status === "operational" ? "animate-pulse" : ""}`} />
              <span className="text-sm text-cyber-white/80 font-medium">{s.name}</span>
            </div>
            <div className="flex items-center gap-4">
              <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-wider text-cyber-white/40 uppercase">{s.uptime} uptime</span>
              <span className={`font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-wider uppercase font-bold ${s.status === "operational" ? "text-emerald-400" : s.status === "maintenance" ? "text-cyan-400" : "text-amber-400"}`}>
                {statusLabels[s.status]}
              </span>
            </div>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
