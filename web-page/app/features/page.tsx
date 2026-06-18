export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const features = [
  { icon: "⚡", title: "Real-Time Monitoring", desc: "Continuously monitors servers, logs, network traffic, and file systems around the clock. Every packet, every process, every change — CyberNova sees it all." },
  { icon: "🛡️", title: "AI Threat Detection", desc: "Separates real threats from false alarms using advanced AI-powered analysis. Instantly notifies and takes action automatically." },
  { icon: "🔒", title: "Auto-Quarantine", desc: "When threats are detected, CyberNova automatically blocks, isolates, and contains them in real time — no human intervention needed." },
  { icon: "🌐", title: "Full Infrastructure Coverage", desc: "From bare-metal servers to cloud instances, database files to network endpoints — protection across every asset." },
  { icon: "📊", title: "Intelligent Log Analysis", desc: "Filters massive log volumes to surface only actionable insights. Zero noise, maximum signal." },
  { icon: "🚀", title: "Zero-Downtime Response", desc: "Adaptive defense that never sleeps. Learns from every scan and adapts to new threats instantly." },
];

export default function FeaturesPage() {
  return (
    <PageLayout title="Features" subtitle="Everything you need to protect your digital infrastructure — powered by AI that never sleeps." accent="Platform Capabilities">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((f, i) => (
          <div key={f.title} className="neon-card p-6 card-enter group" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="text-3xl mb-4">{f.icon}</div>
            <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-cyan uppercase tracking-wider mb-3">{f.title}</h3>
            <p className="text-sm text-cyber-white/70 leading-relaxed">{f.desc}</p>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
