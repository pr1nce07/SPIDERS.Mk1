// SILKTRACE forensic workspace: native SPIDERS capture cases + universal drone-log evidence.
// Routes: #/silktrace (native cases), #/silktrace/<CASE-ID> (case detail), #/silktrace/universal.
import { go, useRoute } from "../lib/nav";
import { Badge, PageTitle, Tabs } from "../components/ui";
import SilktraceCases from "./SilktraceCases";
import SilktraceUniversal from "./SilktraceUniversal";

export const UNIVERSAL_TAB = "universal";

export default function Silktrace() {
  const r = useRoute();
  const universal = r.id === UNIVERSAL_TAB;
  return (
    <div className="col">
      <PageTitle
        title="SILKTRACE"
        sub={universal
          ? "Universal drone forensics · evidence-first intake · unknown-format tolerant · read-only originals"
          : "Native cases · incidents captured by SPIDERS · SHA-256 sealed evidence packages"}
        right={universal ? <Badge v="L0–L3 progressive support" tone="ok" /> : undefined}
      />
      <Tabs
        value={universal ? UNIVERSAL_TAB : "cases"}
        onChange={(t) => go(t === UNIVERSAL_TAB ? `silktrace/${UNIVERSAL_TAB}` : "silktrace")}
        tabs={[{ id: "cases", label: "Native cases" }, { id: UNIVERSAL_TAB, label: "Universal forensics" }]}
      />
      {universal ? <SilktraceUniversal /> : <SilktraceCases caseId={r.id} />}
    </div>
  );
}
