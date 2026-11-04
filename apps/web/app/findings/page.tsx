import type { Metadata } from "next";
import { Providers } from "../providers";
import { FindingsWorkspace } from "./workspace";

export const metadata: Metadata = { title: "Findings | Veyrix" };
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ project?: string; finding?: string }>;
}) {
  const params = await searchParams;
  return (
    <Providers>
      <FindingsWorkspace
        initialProjectId={params.project}
        initialFindingId={params.finding}
      />
    </Providers>
  );
}
