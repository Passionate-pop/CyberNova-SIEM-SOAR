export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const posts = [
  { date: "Jun 3, 2026", title: "How AI is Revolutionizing SOC Operations", excerpt: "Traditional security operations centers are overwhelmed. Here's how AI-powered analysts like CyberNova are changing the game.", tag: "AI Security" },
  { date: "May 28, 2026", title: "Zero-Day Detection: A Machine Learning Approach", excerpt: "Our latest ML models can detect zero-day exploits within seconds of first occurrence — before any signature exists.", tag: "Research" },
  { date: "May 15, 2026", title: "Building Autonomous Incident Response", excerpt: "Why manual incident response is a bottleneck and how CyberNova's auto-quarantine system resolves threats in milliseconds.", tag: "Engineering" },
  { date: "May 2, 2026", title: "The Cost of False Positives in Security", excerpt: "False positives cost enterprises $1.3B annually. Our AI filters them out with 99.7% accuracy.", tag: "Industry" },
];

export default function BlogPage() {
  return (
    <PageLayout title="Blog" subtitle="Insights, research, and updates from the CyberNova team." accent="Latest Articles">
      <div className="space-y-6">
        {posts.map((post, i) => (
          <a key={post.title} href="#" className="block neon-card p-6 card-enter group" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-center gap-3 mb-3">
              <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-widest text-cyber-cyan/50 uppercase">{post.date}</span>
              <span className="font-[family-name:var(--font-orbitron)] text-[0.55rem] tracking-wider text-cyber-purple uppercase px-2 py-0.5 rounded border border-cyber-purple/20 bg-cyber-purple/5">{post.tag}</span>
            </div>
            <h3 className="font-[family-name:var(--font-orbitron)] text-lg font-bold text-cyber-white group-hover:text-cyber-cyan transition-colors duration-300 uppercase tracking-wider mb-2">{post.title}</h3>
            <p className="text-sm text-cyber-white/60 leading-relaxed">{post.excerpt}</p>
          </a>
        ))}
      </div>
    </PageLayout>
  );
}
