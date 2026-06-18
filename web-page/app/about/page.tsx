export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const team = [
  { name: "Security Research", role: "Threat Intelligence", desc: "Constantly hunting new attack vectors and building detection models." },
  { name: "AI Engineering", role: "Machine Learning", desc: "Training the neural networks that power CyberNova's autonomous defense." },
  { name: "Platform Team", role: "Infrastructure", desc: "Building the high-throughput pipeline that processes millions of events per second." },
];

export default function AboutPage() {
  return (
    <PageLayout title="About" subtitle="CyberNova was born from a simple belief: every organization deserves a security chief that never sleeps." accent="Our Mission">
      <div className="neon-card p-6 md:p-8 mb-8">
        <p className="text-sm md:text-base text-cyber-white/70 leading-relaxed mb-4">
          We founded CyberNova because we saw too many organizations drowning in security alerts, false positives, and alert fatigue. The traditional SOC model — hiring more analysts to stare at more dashboards — doesn&apos;t scale.
        </p>
        <p className="text-sm md:text-base text-cyber-white/70 leading-relaxed">
          Our AI-powered SOC analyst monitors your entire infrastructure 24/7, learns from every scan, and responds to threats in milliseconds. Not because it&apos;s programmed to — because it&apos;s trained to think like a hacker and act like a security chief.
        </p>
      </div>
      <h2 className="font-[family-name:var(--font-orbitron)] text-lg font-bold text-cyber-cyan uppercase tracking-wider mb-6">Our Teams</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {team.map((t, i) => (
          <div key={t.name} className="neon-card p-6 card-enter" style={{ animationDelay: `${i * 80}ms` }}>
            <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-white uppercase tracking-wider mb-1">{t.name}</h3>
            <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-widest text-cyber-purple uppercase">{t.role}</span>
            <p className="text-sm text-cyber-white/60 leading-relaxed mt-3">{t.desc}</p>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
