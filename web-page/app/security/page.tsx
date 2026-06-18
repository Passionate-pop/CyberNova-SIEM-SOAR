export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const practices = [
  { title: "Encryption at Rest", desc: "All stored data is encrypted using AES-256 with regularly rotated keys." },
  { title: "Encryption in Transit", desc: "All API communication uses TLS 1.3 with certificate pinning." },
  { title: "SOC 2 Type II", desc: "Independently audited controls for security, availability, and confidentiality." },
  { title: "Zero Trust Architecture", desc: "Every request is authenticated and authorized. No implicit trust." },
  { title: "Data Residency", desc: "Choose your data region. EU, US, or Asia-Pacific — your data stays where you put it." },
  { title: "Penetration Testing", desc: "Regular third-party penetration tests and a responsible disclosure program." },
];

export default function SecurityPage() {
  return (
    <PageLayout title="Security" subtitle="Security isn't just what we sell — it's how we operate. Every layer, every day." accent="Trust & Compliance">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {practices.map((p, i) => (
          <div key={p.title} className="neon-card p-6 card-enter" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-cyan uppercase tracking-wider">{p.title}</h3>
            </div>
            <p className="text-sm text-cyber-white/60 leading-relaxed">{p.desc}</p>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
