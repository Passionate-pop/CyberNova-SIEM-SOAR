import PageHeader from "@/components/page-header";

interface PageLayoutProps {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  accent?: string;
}

export default function PageLayout({ children, title, subtitle, accent }: PageLayoutProps) {
  return (
    <div className="min-h-screen bg-[#020B22] relative overflow-x-hidden page-enter">
      {/* Scanline overlay */}
      <div className="fixed inset-0 z-[2] scanline opacity-15 pointer-events-none" />

      {/* Page header — CSS animations, renders on server */}
      <PageHeader title={title} subtitle={subtitle} accent={accent} />

      {/* Page content — renders immediately on server */}
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pb-20">
        {children}
      </div>
    </div>
  );
}
