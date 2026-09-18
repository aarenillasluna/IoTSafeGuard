import { BrowserRouter, NavLink, Routes, Route, Navigate } from "react-router-dom";
import { Home } from "./pages/Home";
import { DevicesList } from "./pages/DevicesList";
import { DeviceDetail } from "./pages/DeviceDetail";
import { ReportsList } from "./pages/ReportsList";
import { ReportDetail } from "./pages/ReportDetail";
import { CvesList } from "./pages/CvesList";
import { CveDetail } from "./pages/CveDetail";
import { LaunchAudit } from "./pages/LaunchAudit";
import { AuditsList } from "./pages/AuditsList";
import { AuditStream } from "./pages/AuditStream";

export function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <NavLink to="/" end className="brand">
            iotsafeguard
            <span className="brand-suffix">tfm · ciberseguridad iot</span>
          </NavLink>
          <nav>
            <NavLink to="/" end>resumen</NavLink>
            <NavLink to="/devices">dispositivos</NavLink>
            <NavLink to="/reports">reportes</NavLink>
            <NavLink to="/cves">cves</NavLink>
            <NavLink to="/launch">auditar</NavLink>
            <NavLink to="/audits" end>ejecuciones</NavLink>
          </nav>
          <div className="sidebar-foot">
            <span className="dim mono">v0.1</span>
          </div>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/devices" element={<DevicesList />} />
            <Route path="/devices/:deviceKey" element={<DeviceDetail />} />
            <Route path="/reports" element={<ReportsList />} />
            <Route path="/reports/:reportId" element={<ReportDetail />} />
            <Route path="/cves" element={<CvesList />} />
            <Route path="/cves/:cveId" element={<CveDetail />} />
            <Route path="/launch" element={<LaunchAudit />} />
            <Route path="/audits" element={<AuditsList />} />
            <Route path="/audits/:auditId" element={<AuditStream />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
