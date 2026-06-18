export const dynamic = "force-static";

import PageLayout from "@/components/page-layout";

const openings = [
  { title: "Senior ML Engineer", dept: "AI Engineering", location: "Remote", type: "Full-time" },
  { title: "Security Researcher", dept: "Threat Intelligence", location: "Remote", type: "Full-time" },
  { title: "Platform Engineer", dept: "Infrastructure", location: "San Francisco, CA", type: "Full-time" },
  { title: "Frontend Engineer", dept: "Product", location: "Remote", type: "Full-time" },
  { title: "DevRel Advocate", dept: "Developer Relations", location: "Remote", type: "Full-time" },
];

export default function CareersPage() {
  return (
    <PageLayout title="Careers" subtitle="Join the team building the future of autonomous cybersecurity." accent="Open Positions">
      <div className="space-y-4">
        {openings.map((job, i) => (
          <a key={job.title} href="#" className="block neon-card p-5 card-enter group" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="font-[family-name:var(--font-orbitron)] text-sm font-bold text-cyber-white group-hover:text-cyber-cyan transition-colors duration-300 uppercase tracking-wider">{job.title}</h3>
                <span className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-wider text-cyber-purple uppercase">{job.dept}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[0.7rem] text-cyber-white/50">{job.location}</span>
                <span className="font-[family-name:var(--font-orbitron)] text-[0.55rem] tracking-wider text-cyber-cyan/60 uppercase px-2 py-0.5 rounded border border-cyber-cyan/20">{job.type}</span>
              </div>
            </div>
          </a>
        ))}
      </div>
    </PageLayout>
  );
}
