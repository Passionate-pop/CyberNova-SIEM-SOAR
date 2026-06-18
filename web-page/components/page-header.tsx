import Breadcrumb from "@/components/breadcrumb";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  accent?: string;
}

export default function PageHeader({ title, subtitle, accent }: PageHeaderProps) {
  return (
    <div className="relative z-10 pt-28 pb-12 md:pt-36 md:pb-16 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto text-center">
        <Breadcrumb />
        {accent && (
          <p
            className="font-[family-name:var(--font-orbitron)] text-[0.6rem] sm:text-[0.7rem] tracking-[0.4em] text-cyber-purple uppercase mb-4 md:mb-6 font-extrabold"
            style={{ animation: "header-accent 0.4s 0.05s ease-out both" }}
          >
            {accent}
          </p>
        )}
        <h1
          className="font-[family-name:var(--font-orbitron)] text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-extrabold uppercase leading-tight mb-4 md:mb-6"
          style={{
            textShadow: "0 0 10px rgba(105,229,255,0.8), 0 0 30px rgba(105,229,255,0.6), 0 0 60px rgba(105,229,255,0.4), 0 0 100px rgba(105,229,255,0.2)",
            animation: "header-title 0.5s 0.1s ease-out both",
          }}
        >
          {title}
        </h1>
        <div
          className="flex justify-center mb-6 md:mb-8"
          style={{ animation: "header-divider 0.4s 0.2s ease-in-out both" }}
        >
          <div className="h-[1px] w-32 md:w-48 bg-gradient-to-r from-transparent via-cyber-cyan/50 to-transparent" />
        </div>
        {subtitle && (
          <p
            className="font-inter text-sm md:text-base text-cyber-white/80 max-w-2xl mx-auto leading-relaxed font-medium"
            style={{ animation: "header-subtitle 0.4s 0.3s ease-out both" }}
          >
            {subtitle}
          </p>
        )}
      </div>
  );
}
