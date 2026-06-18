export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

export default function TermsPage() {
  return (
    <PageLayout title="Terms of Service" subtitle="The rules and guidelines for using CyberNova's security platform." accent="Legal">
      <div className="space-y-8">
        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">1. Acceptance of Terms</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            By accessing or using CyberNova&apos;s AI-powered SOC analyst platform (&quot;Service&quot;), you agree to be bound by these Terms of Service. If you do not agree to these terms, do not use the Service. These terms apply to all users, including administrators, analysts, and any personnel with access to your CyberNova account.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">2. Service Description</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            CyberNova provides an AI-powered security operations center analyst that monitors your infrastructure, detects threats, and responds to security incidents. The Service includes:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Real-time monitoring of servers, logs, network traffic, and file systems.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>AI-powered threat detection and classification.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Automated incident response and quarantine capabilities.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Security dashboards, alerts, and reporting.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">3. Account Responsibilities</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            You are responsible for:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Maintaining the confidentiality of your account credentials.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>All activity that occurs under your account.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Ensuring that authorized users comply with these terms.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Configuring quarantine and response rules appropriate for your environment.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">4. Acceptable Use</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed mb-4">
            You agree not to:
          </p>
          <ul className="space-y-2 ml-4">
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Use the Service for any unlawful purpose or in violation of any applicable regulations.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Attempt to reverse-engineer, decompile, or extract the AI models or core algorithms.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Share account access with unauthorized third parties.</span>
            </li>
            <li className="text-sm text-cyber-white/60 leading-relaxed flex items-start gap-2">
              <span className="text-cyber-cyan/60 mt-0.5 shrink-0">▸</span>
              <span>Interfere with or disrupt the Service infrastructure.</span>
            </li>
          </ul>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">5. Payment & Billing</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            Paid plans are billed monthly or annually in advance. All fees are non-refundable except as required by law. We reserve the right to modify pricing with 30 days&apos; notice. If you fail to pay on time, we may suspend your access to the Service after a 7-day grace period.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">6. Limitation of Liability</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            CyberNova is a security monitoring and response tool — not a guarantee of zero breaches. While our AI achieves industry-leading detection rates, no security system is infallible. Our liability is limited to the fees paid for the Service in the 12 months preceding the claim. We are not responsible for indirect, incidental, or consequential damages.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">7. Termination</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            Either party may terminate this agreement with 30 days&apos; written notice. Upon termination, your data will be retained for 30 days and then permanently deleted unless you request an earlier deletion. You may export your data at any time during the retention period.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">8. Changes to Terms</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            We may update these terms from time to time. Material changes will be communicated via email or in-app notification at least 30 days before they take effect. Continued use of the Service after changes take effect constitutes acceptance of the updated terms.
          </p>
        </div>

        <div className="neon-card p-6 md:p-8">
          <h2 className="font-[family-name:var(--font-orbitron)] text-base font-bold text-cyber-cyan uppercase tracking-wider mb-4">9. Contact</h2>
          <p className="text-sm text-cyber-white/70 leading-relaxed">
            Questions about these Terms? Contact us at <span className="text-cyber-cyan">legal@cybernova.io</span> or visit our <a href="/contact" className="text-cyber-cyan hover:underline">Contact page</a>.
          </p>
        </div>

        <p className="text-[0.65rem] text-cyber-white/30 text-center">
          Last updated: June 6, 2026
        </p>
      </div>
    </PageLayout>
  );
}
