export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const sections = [
  { title: "Getting Started", items: ["Quick Installation", "First Server Setup", "Connecting Your Network", "Your First Alert"] },
  { title: "Configuration", items: ["Alert Rules Engine", "Notification Channels", "Custom Dashboards", "Retention Policies"] },
  { title: "Integrations", items: ["AWS CloudWatch", "Azure Sentinel", "Google Cloud SCC", "Slack & PagerDuty"] },
  { title: "Advanced", items: ["Custom ML Models", "SOAR Playbooks", "API Automation", "On-Premise Deployment"] },
];

export default function DocsPage() {
  return (
    <PageLayout title="Documentation" subtitle="Everything you need to deploy, configure, and master CyberNova." accent="Knowledge Base">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {sections.map((section, i) => (
          <div key={section.title} className="neon-card p-6 card-enter" style={{ animationDelay: `${i * 80}ms` }}>
            <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-cyan uppercase tracking-wider mb-4">{section.title}</h3>
            <ul className="space-y-2">
              {section.items.map((item) => (
                <li key={item}>
                  <a href="#" className="flex items-center gap-2 text-sm text-cyber-white/60 hover:text-cyber-cyan transition-colors duration-200 group">
                    <span className="text-cyber-cyan/40 group-hover:text-cyber-cyan transition-colors">▸</span> {item}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </PageLayout>
  );
}
