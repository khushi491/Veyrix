"use client";

import { RunPanel } from "./run-panel";
import { useState } from "react";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  ArrowUpRight,
  Box,
  ChevronRight,
  CircleDot,
  Folder,
  Plus,
  Shield,
  Terminal,
} from "lucide-react";
import { z } from "zod";

type Project = {
  id: string;
  name: string;
  description: string;
  created_at: string;
};
type Agent = {
  id: string;
  name: string;
  variant: "vulnerable" | "hardened";
  adapter: string;
};
const projectInput = z.object({
  name: z.string().trim().min(1, "Enter a name").max(120),
  description: z.string().max(2000),
});
async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(
    `/api${path}`,
    body
      ? {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : undefined,
  );
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new Error(
      typeof data?.detail === "string"
        ? data.detail
        : `Request failed (${response.status}). Check that the API is running.`,
    );
  }
  return response.json() as Promise<T>;
}
function Dashboard() {
  const cache = useQueryClient();
  const [selected, setSelected] = useState<string>("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Project[]>("/projects"),
  });
  const projectId = selected || projects.data?.[0]?.id || "";
  const project = projects.data?.find((p) => p.id === projectId);
  const agents = useQuery({
    queryKey: ["agents", projectId],
    queryFn: () => api<Agent[]>(`/projects/${projectId}/agents`),
    enabled: !!projectId,
  });
  const createProject = useMutation({
    mutationFn: (body: z.infer<typeof projectInput>) =>
      api<Project>("/projects", body),
    onSuccess: async (p) => {
      await cache.invalidateQueries({ queryKey: ["projects"] });
      setSelected(p.id);
      setCreating(false);
      setError("");
    },
  });
  const createAgent = useMutation({
    mutationFn: (body: {
      name: string;
      variant: string;
      adapter: string;
      server_variant: string;
    }) => api<Agent>(`/projects/${projectId}/agents`, body),
    onSuccess: async () => {
      await cache.invalidateQueries({ queryKey: ["agents", projectId] });
      setError("");
    },
  });
  return (
    <div className="workspace">
      <aside>
        <a href="/" className="brand">
          <Shield size={25} /> VEYRIX <span>α</span>
        </a>
        <div className="workspace-label">
          LOCAL WORKSPACE <CircleDot size={12} />
        </div>
        <nav>
          <a href="#overview" className="active">
            <Box size={17} /> Overview
          </a>
          <a href="#projects">
            <Folder size={17} /> Projects
          </a>
          <a href="#agents">
            <Shield size={17} /> Agents
          </a>
        </nav>
        <div className="aside-note">
          <Terminal size={18} />
          <strong>Built for the boundary.</strong>
          <p>Break your agents before attackers do.</p>
          <span>FOUNDATION · v0.1.0</span>
        </div>
      </aside>
      <main id="overview">
        <header>
          <span>
            Workspace <ChevronRight size={13} /> Overview
          </span>
          <span className="dev">
            <i /> Local development
          </span>
        </header>
        <section className="content">
          <div className="eyebrow">AGENT SECURITY WORKSPACE</div>
          <div className="heading">
            <div>
              <h1>Know your boundaries.</h1>
              <p>
                Connect your agents. Build an evidence-backed security practice.
              </p>
            </div>
            <button onClick={() => setCreating(true)}>
              <Plus size={16} /> New project
            </button>
          </div>
          <div className="metrics">
            <article>
              <span>Projects in this view</span>
              <strong>{projects.data?.length ?? "—"}</strong>
              <small>Persistent workspace configuration</small>
            </article>
            <article>
              <span>Agents in selected project</span>
              <strong>{projectId ? (agents.data?.length ?? "—") : "—"}</strong>
              <small>Local adapter configurations</small>
            </article>
            <article>
              <span>Security assessment</span>
              <strong className="unscored">Insufficient coverage</strong>
              <small>Synthetic fixtures; no numeric score</small>
            </article>
          </div>
          {(projects.error || agents.error) && (
            <div role="alert" className="error">
              {(projects.error || agents.error)?.message}
              <button
                className="secondary"
                onClick={() => {
                  void projects.refetch();
                  void agents.refetch();
                }}
              >
                Retry
              </button>
            </div>
          )}
          <div className="columns">
            <section className="panel" id="projects">
              <div className="panel-heading">
                <h2>Projects</h2>
                <span>01 / CONFIGURE</span>
              </div>
              {projects.isPending ? (
                <p className="empty">Loading projects…</p>
              ) : projects.data?.length ? (
                <div className="project-list">
                  {projects.data.map((p) => (
                    <button
                      className={
                        p.id === projectId ? "project selected" : "project"
                      }
                      key={p.id}
                      onClick={() => setSelected(p.id)}
                    >
                      <Folder size={18} />
                      <div>
                        <strong>{p.name}</strong>
                        <small>
                          {p.description || "Local security project"}
                        </small>
                      </div>
                      <ChevronRight size={15} />
                    </button>
                  ))}
                </div>
              ) : (
                <div className="empty">
                  <Folder size={28} />
                  <h3>Your first security workspace</h3>
                  <p>
                    Create a project to organize agents and their permission
                    policies.
                  </p>
                  <button
                    className="secondary"
                    onClick={() => setCreating(true)}
                  >
                    Create project <ArrowUpRight size={14} />
                  </button>
                </div>
              )}
            </section>
            <section className="panel" id="agents">
              <div className="panel-heading">
                <h2>
                  {project ? `${project.name} / Agents` : "Agent registry"}
                </h2>
                <span>02 / CONNECT</span>
              </div>
              {!projectId ? (
                <div className="empty">
                  <Shield size={28} />
                  <h3>Start with a project</h3>
                  <p>Your registered agents will appear here.</p>
                </div>
              ) : (
                <>
                  <div className="agent-list">
                    {agents.isPending ? (
                      <p>Loading agents…</p>
                    ) : agents.data?.length ? (
                      agents.data.map((a) => (
                        <div className="agent" key={a.id}>
                          <Shield size={19} />
                          <div>
                            <strong>{a.name}</strong>
                            <small>
                              {a.adapter} adapter · {a.variant} fixture
                            </small>
                          </div>
                          <span className="tag">Registered</span>
                        </div>
                      ))
                    ) : (
                      <p className="muted">
                        No agents registered in this project.
                      </p>
                    )}
                  </div>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      const data = new FormData(e.currentTarget);
                      const name = String(data.get("name")).trim();
                      if (!name) {
                        setError("Enter an agent name");
                        return;
                      }
                      createAgent.mutate({
                        name,
                        variant: String(data.get("variant")),
                        adapter: String(data.get("adapter")),
                        server_variant: String(data.get("server_variant")),
                      });
                    }}
                  >
                    <label htmlFor="agent-name">
                      Register an example agent
                    </label>
                    <div className="form-row">
                      <input
                        id="agent-name"
                        name="name"
                        placeholder="e.g. Payments assistant"
                        required
                        maxLength={120}
                      />
                      <select name="variant" aria-label="Agent variant">
                        <option value="hardened">Hardened</option>
                        <option value="vulnerable">Vulnerable</option>
                      </select>
                    </div>
                    <div className="form-row integration-row">
                      <select name="adapter" aria-label="Integration adapter">
                        <option value="local">Local fixture</option>
                        <option value="mcp">MCP stdio fixture</option>
                      </select>
                      <select
                        name="server_variant"
                        aria-label="MCP server policy enforcement"
                      >
                        <option value="vulnerable">Unguarded MCP server</option>
                        <option value="hardened">
                          Policy-enforcing MCP server
                        </option>
                      </select>
                    </div>
                    <p className="form-hint">
                      Synthetic fixtures only. No production credentials
                      required.
                    </p>
                    <button disabled={createAgent.isPending}>
                      {createAgent.isPending
                        ? "Registering…"
                        : "Register agent"}
                      <Plus size={14} />
                    </button>
                  </form>
                </>
              )}
            </section>
          </div>
          <RunPanel key={projectId} agents={agents.data ?? []} />
          <div className="notice">
            <CircleDot size={18} />
            <div>
              <strong>A clear starting point.</strong>
              <p>
                Local and MCP fixtures execute through the background worker.
                These deterministic tests validate the assessment pipeline; they
                do not measure external model robustness.
              </p>
            </div>
          </div>
          {creating && (
            <section className="panel create-panel" aria-label="Create project">
              <div className="panel-heading">
                <h2>New project</h2>
                <button
                  className="secondary"
                  onClick={() => setCreating(false)}
                >
                  Cancel
                </button>
              </div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const result = projectInput.safeParse(
                    Object.fromEntries(new FormData(e.currentTarget)),
                  );
                  if (!result.success) {
                    setError(result.error.issues[0].message);
                    return;
                  }
                  createProject.mutate(result.data);
                }}
              >
                <label htmlFor="project-name">Project name</label>
                <input
                  id="project-name"
                  name="name"
                  required
                  maxLength={120}
                  placeholder="Your agent workspace"
                  autoFocus
                />
                <label htmlFor="description">Description</label>
                <textarea
                  id="description"
                  name="description"
                  maxLength={2000}
                  placeholder="What does your agent do?"
                />
                <button disabled={createProject.isPending}>
                  {createProject.isPending ? "Creating…" : "Create project"}
                </button>
              </form>
            </section>
          )}
          {(error || createProject.error || createAgent.error) && (
            <p className="error" role="alert">
              {error ||
                createProject.error?.message ||
                createAgent.error?.message}
            </p>
          )}
          <footer>
            <span>Security for Autonomous Intelligence.</span>
            <span>Local workspace · Development access enabled</span>
          </footer>
        </section>
      </main>
    </div>
  );
}
export default function Page() {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: 1 } } }),
  );
  return (
    <QueryClientProvider client={client}>
      <Dashboard />
    </QueryClientProvider>
  );
}
