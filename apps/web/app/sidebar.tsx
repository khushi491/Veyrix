import {
  Box,
  Bug,
  CircleDot,
  Folder,
  FlaskConical,
  Shield,
  Terminal,
} from "lucide-react";
import { demoMode } from "./demo-mode";

export function Sidebar({
  active = "overview",
  projectId,
}: {
  active?: "overview" | "findings";
  projectId?: string;
}) {
  return (
    <aside>
      <a href="/" className="brand">
        <Shield size={25} /> VEYRIX <span>α</span>
      </a>
      <div className="workspace-label">
        {demoMode ? "READ-ONLY DEMO" : "LOCAL WORKSPACE"} <CircleDot size={12} />
      </div>
      <nav>
        <a href="/" className={active === "overview" ? "active" : ""}>
          <Box size={17} />
          Overview
        </a>
        <a href="/#projects">
          <Folder size={17} />
          Projects
        </a>
        <a href="/#agents">
          <Shield size={17} />
          Agents
        </a>
        <a href="/#tests">
          <FlaskConical size={17} />
          Security Tests
        </a>
        <a
          href={projectId ? `/findings?project=${projectId}` : "/findings"}
          className={active === "findings" ? "active" : ""}
        >
          <Bug size={17} />
          Findings
        </a>
      </nav>
      <div className="aside-note">
        <Terminal size={18} />
        <strong>Built for the boundary.</strong>
        <p>Break your agents before attackers do.</p>
        <span>{demoMode ? "PUBLIC SNAPSHOT · v0.1.0" : "LOCAL MVP · v0.1.0"}</span>
      </div>
    </aside>
  );
}
