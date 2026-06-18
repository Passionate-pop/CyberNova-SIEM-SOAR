import Link from "next/link";

const footerLinks = {
  product: [
    { label: "Features", href: "/features" },
    { label: "Platform", href: "/platform" },
    { label: "Pricing", href: "/pricing" },
    { label: "Changelog", href: "/changelog" },
  ],
  resources: [
    { label: "Documentation", href: "/docs" },
    { label: "API Reference", href: "/api" },
    { label: "Blog", href: "/blog" },
    { label: "Status", href: "/status" },
  ],
  company: [
    { label: "About", href: "/about" },
    { label: "Careers", href: "/careers" },
    { label: "Contact", href: "/contact" },
    { label: "Security", href: "/security" },
  ],
};

const socialLinks = [
  {
    label: "GitHub",
    href: "#github",
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
      </svg>
    ),
  },
  {
    label: "Twitter",
    href: "#twitter",
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 4s-.7 2.1-2 3.4c1.6 10-9.4 17.3-18 11.6 2.2.1 4.4-.6 6-2C3 15.5.5 9.6 3 5c2.2 2.6 5.6 4.1 9 4-.9-4.2 4-6.6 7-3.8 1.1 0 3-1.2 3-1.2z" />
      </svg>
    ),
  },
  {
    label: "LinkedIn",
    href: "#linkedin",
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z" />
        <rect x="2" y="9" width="4" height="12" />
        <circle cx="4" cy="4" r="2" />
      </svg>
    ),
  },
  {
    label: "Discord",
    href: "#discord",
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 6L6.5 18M6.5 6L18 18" />
      </svg>
    ),
  },
];

export default function Footer() {
  return (
    <footer className="relative z-[55] border-t border-cyber-cyan/10">
      <div
        className="relative"
        style={{
          background: "linear-gradient(180deg, rgba(2, 11, 34, 0.95) 0%, rgba(2, 11, 34, 1) 100%)",
          backdropFilter: "blur(20px)",
        }}
      >
        {/* Top glow line */}
        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyber-cyan/30 to-transparent" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 md:py-16">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-8 md:gap-12">
            {/* Brand column */}
            <div className="col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 rounded-full overflow-hidden border border-cyber-cyan/30">
                  <img src="/logo.png" alt="CyberNova Logo" width={32} height={32} className="w-full h-full object-cover" />
                </div>
                <span className="font-[family-name:var(--font-orbitron)] text-xs font-bold tracking-[0.2em] text-cyber-white/80 uppercase">
                  CyberNova
                </span>
              </div>
              <p className="text-sm text-cyber-white/30 leading-relaxed max-w-xs mb-6">
                AI-powered SOC analyst that monitors your servers, logs, network, and files 24/7. Thinks like a hacker. Acts like a security chief.
              </p>
              <div className="flex items-center gap-3">
                {socialLinks.map((social) => (
                  <a
                    key={social.label}
                    href={social.href}
                    aria-label={social.label}
                    className="w-8 h-8 rounded-md border border-cyber-cyan/15 bg-cyber-cyan/5 flex items-center justify-center text-cyber-cyan/40 hover:text-cyber-cyan hover:border-cyber-cyan/40 hover:bg-cyber-cyan/10 transition-all duration-300"
                  >
                    {social.icon}
                  </a>
                ))}
              </div>
            </div>

            {/* Link columns */}
            {Object.entries(footerLinks).map(([category, links]) => (
              <div key={category} className="footer-tilt-container">
                <h4 className="font-[family-name:var(--font-orbitron)] text-[0.6rem] tracking-[0.2em] text-cyber-cyan/50 uppercase mb-4">
                  {category}
                </h4>
                <ul className="space-y-2">
                  {links.map((link) => (
                    <li key={link.label}>
                      <Link
                        href={link.href}
                        className="group/link footer-tilt-item relative flex items-center gap-2 px-3 py-2 -mx-3 rounded-md text-sm text-cyber-white/40 hover:text-cyber-cyan border border-transparent hover:border-cyber-cyan/20 hover:bg-cyber-cyan/5"
                      >
                        <span className="w-0 group-hover/link:w-1.5 h-[1px] bg-cyber-cyan transition-all duration-300 group-hover/link:opacity-80" />
                        <span className="relative z-10 font-medium tracking-wide">{link.label}</span>
                        <span className="ml-auto opacity-0 -translate-x-1 group-hover/link:opacity-100 group-hover/link:translate-x-0 transition-all duration-300 text-cyber-cyan/50">
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M5 12h14" /><path d="M12 5l7 7-7 7" />
                          </svg>
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Bottom bar */}
          <div className="mt-12 pt-6 border-t border-cyber-cyan/8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-[0.65rem] text-cyber-white/20 tracking-wider">
              &copy; {new Date().getFullYear()} CyberNova. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link href="/privacy" className="text-[0.65rem] text-cyber-white/20 hover:text-cyber-cyan/50 transition-colors">
                Privacy Policy
              </Link>
              <Link href="/terms" className="text-[0.65rem] text-cyber-white/20 hover:text-cyber-cyan/50 transition-colors">
                Terms of Service
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
