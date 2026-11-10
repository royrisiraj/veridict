"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { LoaderCircle } from "lucide-react";
import EvidencePassport from "@/components/EvidencePassport";
import { api } from "@/lib/api";
import type { Report } from "@/lib/types";

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    api<Report>(`reports/${id}`).then((r) => { if (active) setReport(r); }).catch((e) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [id]);
  if (error) return <div className="empty-state"><h1>Passport unavailable.</h1><p role="alert">{error}</p><Link href="/" className="button primary">Return to investigation desk</Link></div>;
  if (!report) return <div className="empty-state"><LoaderCircle className="spin"/><p>Retrieving sealed evidence…</p></div>;
  return <EvidencePassport key={id} report={report}/>;
}
