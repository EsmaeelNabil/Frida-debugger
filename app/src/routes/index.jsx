import { Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import LoadingSpinner from '@/components/common/LoadingSpinner.jsx';

const Home = lazy(() => import('../pages/Home.jsx'));
const DeviceDetails = lazy(() => import('../pages/DeviceDetails.jsx'));
const AppDashboard = lazy(() => import('../pages/AppDashboard.jsx'));

export default function AppRoutes() {
    return (
        <Suspense fallback={<LoadingSpinner />}>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/device/:deviceId" element={<DeviceDetails />} />
                <Route path="/app/:deviceId/:appName" element={<AppDashboard />} />
                <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
        </Suspense>
    );
}
