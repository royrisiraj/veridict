import type { components } from "./api.generated";
export type Report = components["schemas"]["InvestigationReport"];
export type Bundle = Report["bundle"];
export type Verification = components["schemas"]["VerificationResponse"];
export type Fixture = components["schemas"]["FixtureMetadata"];
export type InvestigationInput = components["schemas"]["InvestigateRequest"];
export type TamperResult = components["schemas"]["TamperResponse"];
export type Mutation = components["schemas"]["TamperRequest"]["mutation"];
export type Health = components["schemas"]["HealthResponse"];
export type Risk = components["schemas"]["RiskClass"];

export const riskLabels: Record<Risk, string> = {
  LOW_RISK: "Low risk", SUSPICIOUS: "Suspicious", HIGH_RISK: "High risk",
  CONFIRMED_MALICIOUS: "Confirmed malicious", INCONCLUSIVE: "Inconclusive",
};
