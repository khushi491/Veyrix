import type { Metadata } from "next";
import { loadKitScan } from "../../lib/kit-scan";
import { Sidebar } from "../sidebar";
import { KitView } from "./view";

// Read the publication on every request. `revalidate` prerenders this route and
// serves that HTML while a new one is generated in the background, so a visitor
// can keep seeing an older kit-scans file for hours after it is published.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Red-team kit | Veyrix",
  description:
    "Scheduled scan of a deliberately vulnerable sample agent and the hardened fixture.",
};

export default async function Page() {
  const loaded = await loadKitScan();
  return (
    <div className="workspace">
      <Sidebar active="kit" />
      <main id="kit">
        <KitView loaded={loaded} />
      </main>
    </div>
  );
}
