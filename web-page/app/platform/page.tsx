export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const layers = [
  { name: "Ingestion Layer", desc: "High-throughput data ingestion from servers, network taps, log files, and cloud APIs. Processes millions of events per second.", tech: "Kafka · Fluentd · Filebeat" },
  { name: "Analysis Engine", desc: "AI-powered threat analysis with ML models trained on billions of security events. Pattern recognition, anomaly detection, and behavioral analysis.", tech: "Custom ML Pipeline · Neural Networks" },
  { name: "Response Orchestrator", desc: "Automated incident response with configurable playbooks. Block, isolate, notify, and remediate — all in milliseconds.", tech: "SOAR Integration · Custom Actions" },
  { name: "Dashboard & Alerts", desc: "Real-time visualization of your security posture. Customizable alerts via email, Slack, PagerDuty, and webhooks.", tech: "React · WebSocket · GraphQL" },
];

export default function PlatformPage() {
  return (
    <PageLayout title="Platform" subtitle="Built on a four-layer architecture designed for speed, accuracy, and scale." accent="System Architecture">
      <div className="space-y-6">
        {layers.map((layer, i) => (
          <div key={layer.name} className="neon-card p-6 card-enter" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-center gap-4 mb-3">
              <span className="font-[family-name:var(--font-orbitron)] text-2xl font-extrabold text-cyber-cyan/30">0{i + 1}</span>
              <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-cyan uppercase tracking-wider">{layer.name}</h3>
            </div>
            <p className="text-sm text-cyber-white/70 leading-relaxed mb-3">{layer.desc}</p>
            <span className="inline-block font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-widest text-cyber-purple uppercase">{layer.tech}</span>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
