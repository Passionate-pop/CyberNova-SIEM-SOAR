import type { Metadata } from "next";
import localFont from "next/font/local";
import Navbar from "@/components/navbar";
import Footer from "@/components/footer";
import "./globals.css";

const inter = localFont({
  src: "../fonts/Inter-Regular.woff2",
  variable: "--font-inter",
  display: "swap",
});

const orbitron = localFont({
  src: [
    { path: "../fonts/Orbitron-Regular.woff2", weight: "400", style: "normal" },
    { path: "../fonts/Orbitron-Bold.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-orbitron",
  display: "swap",
});

export const metadata: Metadata = {
  title: "CYBERNOVA — AI Powered SOC Analyst",
  description:
    "Thinks Like A Hacker. Acts Like A Security Chief. AI-powered security operations center analyst that protects your digital frontier.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${orbitron.variable}`}>
      <body className="antialiased">
        <Navbar />
        {children}
        <Footer />
      </body>
    </html>
  );
}
