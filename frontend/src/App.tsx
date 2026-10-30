import { Routes, Route } from 'react-router-dom';
import DashboardLayout from './layouts/DashboardLayout';
import Dashboard from './pages/Dashboard';
import EC2Inventory from './pages/EC2Inventory';
import S3Inventory from './pages/S3Inventory';
import Findings from './pages/Findings';
import ScanHistory from './pages/ScanHistory';

function App() {
  return (
    <DashboardLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/instances" element={<EC2Inventory />} />
        <Route path="/buckets" element={<S3Inventory />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/history" element={<ScanHistory />} />
      </Routes>
    </DashboardLayout>
  );
}

export default App;
