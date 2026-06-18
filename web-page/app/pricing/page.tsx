export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const plans = [
  { name: "Starter", price: "$49", period: "/mo", desc: "For small teams getting started with AI security.", features: ["Up to 5 servers", "Basic threat detection", "Email alerts", "7-day log retention", "Community support"], highlight: false },
  { name: "Professional", price: "$199", period: "/mo", desc: "For growing teams that need full protection.", features: ["Up to 25 servers", "Advanced AI detection", "Auto-quarantine", "30-day log retention", "Slack/PagerDuty alerts", "Priority support"], highlight: true },
  { name: "Enterprise", price: "Custom", period: "", desc: "For organizations with complex infrastructure.", features: ["Unlimited servers", "Custom ML models", "Full SOAR integration", "Unlimited retention", "Dedicated support", "SLA guarantee", "On-premise option"], highlight: false },
];

export default function PricingPage() {
  return (
    <PageLayout title="Pricing" subtitle="Simple, transparent pricing that scales with your infrastructure." accent="Choose Your Protection">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan, i) => (
          <div key={plan.name} className={`p-6 border card-enter ${plan.highlight ? "neon-card border-cyber-cyan/50 glow-pulse" : "neon-card border-cyber-cyan/15"}`} style={{ animationDelay: `${i * 80}ms` }}>
            {plan.highlight && <div className="font-[family-name:var(--font-orbitron)] text-[0.55rem] tracking-[0.3em] text-cyber-cyan uppercase mb-3 font-bold">Most Popular</div>}
            <h3 className="font-[family-name:var(--font-orbitron)] text-lg font-bold text-cyber-white uppercase tracking-wider mb-2">{plan.name}</h3>
            <div className="flex items-baseline gap-1 mb-3">
              <span className="font-[family-name:var(--font-orbitron)] text-3xl font-extrabold text-cyber-cyan">{plan.price}</span>
              {plan.period && <span className="text-sm text-cyber-white/50">{plan.period}</span>}
            </div>
            <p className="text-sm text-cyber-white/60 mb-6">{plan.desc}</p>
            <ul className="space-y-2 mb-6">
              {plan.features.map((f) => (
                <li key={f} className="flex items-center gap-2 text-sm text-cyber-white/70">
                  <span className="text-cyber-cyan">▸</span> {f}
                </li>
              ))}
            </ul>
            <a href="/contact" className={`block text-center py-3 rounded-lg font-[family-name:var(--font-orbitron)] text-[0.7rem] font-bold tracking-wider uppercase transition-all duration-300 ${plan.highlight ? "bg-cyber-cyan/15 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan/25" : "border border-cyber-cyan/20 text-cyber-white/60 hover:border-cyber-cyan/40 hover:text-cyber-cyan"}`}>
              Get Started
            </a>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
