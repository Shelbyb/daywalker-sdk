import type { ApiClient } from "../api/index.js";

/**
 * Record a deploy marker through the management API: `POST /api/v1/projects/{project}/deploys`
 * (scope `deploy:create`). DevPulse shows it on error, log, Web Vitals and SLO charts.
 */

export type DeployInput = {
  /** e.g. "production". */
  environment: string;
  release?: string;
  /** Commit SHA. */
  sha?: string;
  /** Branch or tag. */
  ref?: string;
  /** Link to the CI run or release page. */
  url?: string;
  description?: string;
  /** Defaults to now on the server. */
  deployedAt?: Date | string;
};

export type Deploy = DeployInput & { id: string; [key: string]: unknown };

export async function recordDeploy(api: Pick<ApiClient, "post">, project: string, input: DeployInput): Promise<Deploy> {
  if (!project) throw new Error("project is required");
  if (!input?.environment) throw new Error("environment is required");
  const body = { ...input, deployedAt: input.deployedAt instanceof Date ? input.deployedAt.toISOString() : input.deployedAt };
  const res = await api.post<Deploy>(`/api/v1/projects/${encodeURIComponent(project)}/deploys`, body);
  return res.data;
}
