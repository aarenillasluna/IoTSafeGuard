/** Visor de reporte: embebe el HTML existente vía iframe + enlace SARIF. */
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";

export function ReportDetail() {
  const { reportId = "" } = useParams<{ reportId: string }>();

  return (
    <div>
      <div className="row spread" style={{ marginBottom: "1rem" }}>
        <div>
          <div style={{ fontSize: ".8rem", marginBottom: ".25rem" }}>
            <Link to="/reports" className="dim">← reportes</Link>
          </div>
          <h2 style={{ margin: 0 }}>Reporte</h2>
          <div className="dim mono" style={{ fontSize: ".75rem" }}>
            {reportId.replace(/^audit_report_/, "")}
          </div>
        </div>
        <div className="row">
          <a
            className="tag"
            href={api.reportHtmlUrl(reportId)}
            target="_blank"
            rel="noreferrer"
            style={{ padding: ".3rem .6rem" }}
          >
            abrir HTML aparte
          </a>
          <a
            className="tag accent"
            href={api.reportSarifUrl(reportId)}
            download
            style={{ padding: ".3rem .6rem" }}
          >
            descargar SARIF
          </a>
        </div>
      </div>

      <iframe
        title={`Reporte ${reportId}`}
        src={api.reportHtmlUrl(reportId)}
        className="iframe-report"
      />
    </div>
  );
}
