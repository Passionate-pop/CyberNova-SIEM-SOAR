"use client";

import { useState } from "react";
import PageLayout from "@/components/page-layout";

export const dynamic = "force-static";

export default function ContactPage() {
  const [submitted, setSubmitted] = useState(false);

  return (
    <PageLayout title="Contact" subtitle="Have questions? Need a demo? We'd love to hear from you." accent="Get in Touch">
      <div className="max-w-xl mx-auto">
        {submitted ? (
          <div className="neon-card p-8 border border-cyber-cyan/20 text-center">
            <div className="text-4xl mb-4">✓</div>
            <h3 className="font-[family-name:var(--font-orbitron)] text-lg font-bold text-cyber-cyan uppercase tracking-wider mb-2">Message Sent</h3>
            <p className="text-sm text-cyber-white/60">We&apos;ll get back to you within 24 hours.</p>
          </div>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); setSubmitted(true); }} className="space-y-5">
            <div>
              <label className="block font-[family-name:var(--font-orbitron)] text-[0.65rem] tracking-widest text-cyber-cyan/60 uppercase mb-2">Name</label>
              <input type="text" required className="w-full bg-cyber-deep/40 border border-cyber-cyan/15 rounded-lg px-4 py-3 text-sm text-cyber-white/80 focus:border-cyber-cyan/50 focus:outline-none transition-colors" placeholder="Your name" />
            </div>
            <div>
              <label className="block font-[family-name:var(--font-orbitron)] text-[0.65rem] tracking-widest text-cyber-cyan/60 uppercase mb-2">Email</label>
              <input type="email" required className="w-full bg-cyber-deep/40 border border-cyber-cyan/15 rounded-lg px-4 py-3 text-sm text-cyber-white/80 focus:border-cyber-cyan/50 focus:outline-none transition-colors" placeholder="you@company.com" />
            </div>
            <div>
              <label className="block font-[family-name:var(--font-orbitron)] text-[0.65rem] tracking-widest text-cyber-cyan/60 uppercase mb-2">Subject</label>
              <select className="w-full bg-cyber-deep/40 border border-cyber-cyan/15 rounded-lg px-4 py-3 text-sm text-cyber-white/80 focus:border-cyber-cyan/50 focus:outline-none transition-colors">
                <option>General Inquiry</option>
                <option>Request Demo</option>
                <option>Partnership</option>
                <option>Support</option>
              </select>
            </div>
            <div>
              <label className="block font-[family-name:var(--font-orbitron)] text-[0.65rem] tracking-widest text-cyber-cyan/60 uppercase mb-2">Message</label>
              <textarea required rows={5} className="w-full bg-cyber-deep/40 border border-cyber-cyan/15 rounded-lg px-4 py-3 text-sm text-cyber-white/80 focus:border-cyber-cyan/50 focus:outline-none transition-colors resize-none" placeholder="Tell us about your needs..." />
            </div>
            <button type="submit" className="w-full py-3 rounded-lg font-[family-name:var(--font-orbitron)] text-[0.7rem] font-bold tracking-wider uppercase bg-cyber-cyan/15 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan/25 transition-all duration-300">
              Send Message
            </button>
          </form>
        )}
      </div>
    </PageLayout>
  );
}
