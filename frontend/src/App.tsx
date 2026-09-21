import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { JobProvider } from "./context/JobContext";
import AppLayout from "./layout/AppLayout";
import Landing from "./pages/Landing";
import Analyzer from "./pages/Analyzer";
import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Attackers from "./pages/Attackers";
import AttackerDetail from "./pages/AttackerDetail";
import TimelinePage from "./pages/TimelinePage";
import GeoMapPage from "./pages/GeoMapPage";
import Reports from "./pages/Reports";
import Rules from "./pages/Rules";
import SettingsPage from "./pages/Settings";

export default function App() {
  return (
    <JobProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/app" element={<AppLayout />}>
            <Route index element={<Navigate to="dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="analyzer" element={<Analyzer />} />
            <Route path="threats" element={<Threats />} />
            <Route path="attackers" element={<Attackers />} />
            <Route path="attackers/:ip" element={<AttackerDetail />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="geo" element={<GeoMapPage />} />
            <Route path="reports" element={<Reports />} />
            <Route path="rules" element={<Rules />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </JobProvider>
  );
}
