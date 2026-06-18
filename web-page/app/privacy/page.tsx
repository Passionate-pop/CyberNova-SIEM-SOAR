export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

export default function PrivacyPage() {
  return (
    <PageLayout title="Privacy Policy" subtitle="Your data security and privacy are foundational to everything we build." accent="Legal">
      <div className="space-y-8">
        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">1. Information We Collect</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            When you use CyberNova, we collect information necessary to provide and improve our AI-powered security services. This includes:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span><strong className="text-cyber-white/80">Account Information:</strong> Name, email address, company name, and billing details when you register for an account.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span><strong className="text-cyber-white/80">Security Data:</strong> Server logs, network traffic metadata, file system events, and threat detection results from your monitored infrastructure.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span><strong className="text-cyber-white/80">Usage Data:</strong> Interactions with the CyberNova dashboard, API calls, and feature usage patterns.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">2. How We Use Your Data</h2>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>To operate, maintain, and improve the CyberNova platform and its AI detection capabilities.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>To detect, prevent, and respond to security threats targeting your infrastructure.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>To communicate with you about service updates, security advisories, and billing.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>To comply with legal obligations and enforce our terms of service.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">3. Data Protection</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            We implement industry-leading security measures to protect your data:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>AES-256 encryption at rest for all stored data.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>TLS 1.3 encryption in transit for all API communication.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>SOC 2 Type II certified infrastructure and processes.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Regular third-party penetration testing and security audits.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">4. Data Retention</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            Security log data is retained according to your plan: 7 days (Starter), 30 days (Professional), or unlimited (Enterprise). Account information is retained for the duration of your subscription and for 30 days after cancellation. You may request deletion of your data at any time by contacting our support team.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">5. Your Rights</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            You have the right to:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Access, correct, or delete your personal information.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Export your security data in standard formats.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Choose your data residency region (EU, US, or Asia-Pacific).</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Opt out of non-essential data processing.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">6. Contact Us</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            If you have questions about this Privacy Policy or our data practices, please contact us at <span className="text-cyber-cyan">privacy@cybernova.io</span> or visit our <a href="/contact" className="text-cyber-cyan hover:underline">Contact page</a>.
          </p>
        </div>

        <p className="text-[0.65rem] text-cyber-white/30 text-center">
          Last updated: June 6, 2026
        </p>
      </div>
    </PageLayout>
  );
}
