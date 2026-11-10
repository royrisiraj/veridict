import type { Metadata } from "next";
import Link from "next/link";
import { ShieldCheck, ArrowUpRight } from "lucide-react";
import "./globals.css";
import DeploymentNotice from "@/components/DeploymentNotice";

export const metadata: Metadata = { title: "VERIDICT — Verify the evidence", description: "Don't just trust the warning. Verify the evidence. Powered by EVIDENCE//GATE." };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>
    <header className="topbar"><div className="shell nav">
      <Link href="/" className="brand" aria-label="VERIDICT home"><span className="brand-icon"><ShieldCheck size={23} /></span>VERIDICT<span className="brand-dot">.</span></Link>
      <span className="nav-label">SECURITY INTELLIGENCE / EVIDENCE INTEGRITY</span>
      <Link href="/#sandbox" className="nav-link">Investigation desk <ArrowUpRight size={14}/></Link>
    </div></header>
    <div className="shell"><DeploymentNotice/></div>
    <main className="shell">{children}</main>
    <footer className="shell footer"><span>VERIDICT / EVIDENCE//GATE</span><span>Don&apos;t just trust the warning. Verify the evidence.</span><span>SEALED-EVIDENCE/1</span></footer>
  </body></html>;
}
