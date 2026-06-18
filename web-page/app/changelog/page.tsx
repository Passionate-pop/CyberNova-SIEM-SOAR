export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const entries = [
  { date: "June 2026", version: "v2.4.0", title: "Adaptive AI Engine", changes: ["New adaptive ML models that learn from your environment", "Improved threat detection accuracy by 34%", "Real-time behavioral analysis"] },
  { date: "May 2026", version: "v2.3.0", title: "Auto-Quarantine Pro", changes: ["Automatic isolation of compromised endpoints", "One-click remediation workflows", "Custom quarantine rules engine"] },
  { date: "April 2026", version: "v2.2.0", title: "Network Defense Grid", changes: ["Full network traffic analysis", "DDoS detection and mitigation", "Encrypted traffic inspection"] },
  { date: "March 2026", version: "v2.1.0", title: "Cloud Integration", changes: ["AWS, Azure, GCP native support", "Multi-cloud security dashboard", "Cloud compliance reporting"] },
  { date: "February 2026", version: "v2.0.0", title: "CyberNova Core Launch", changes: ["AI-powered SOC analyst platform", "Real-time monitoring and alerting", "Autonomous threat response"] },
];

export default function ChangelogPage() {
  return (
    <PageLayout title="Changelog" subtitle="Every update, improvement, and new feature — tracked transparently." accent="Release History">
      <div className="space-y-8">
        {entries.map((entry) => (
          <div key={entry.version} className="relative pl-8 border-l border-cyber-cyan/20">
            <div className="absolute left-0 top-0 w-3 h-3 -translate-x-[7px] rounded-full bg-cyber-cyan/60 border-2 border-cyber-cyan" />
            <div className="flex items-center gap-3 mb-2">
              <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-widest text-cyber-purple uppercase">{entry.date}</span>
              <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-widest text-cyber-cyan/60 uppercase">{entry.version}</span>
            </div>
            <h3 className="font-[family-name:var(--font-orbitron)] text-lg font-bold text-cyber-white uppercase tracking-wider mb-3">{entry.title}</h3>
            <ul className="space-y-1.5">
              {entry.changes.map((c) => (
                <li key={c} className="flex items-start gap-2 text-sm text-cyber-white/60">
                  <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span> {c}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
