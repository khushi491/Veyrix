import type { Metadata } from "next";
import { loadKitScan } from "../../lib/kit-scan";
import { Sidebar } from "../sidebar";
import { KitView } from "./view";

export const revalidate = 900;

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
