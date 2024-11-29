import { useParams } from 'react-router-dom';
import { useDeviceApps } from '@/hooks/useDeviceApps.js';
import { Alert, AlertDescription } from '@/components/ui/alert.jsx';
import AppList from '@/components/apps/AppList.jsx';
import LoadingSpinner from '@/components/common/LoadingSpinner.jsx';

export default function DeviceDetails() {
    const { deviceId } = useParams();
    const { data: apps, isLoading, error } = useDeviceApps(deviceId);

    if (isLoading) return <LoadingSpinner />;

    if (error) {
        return (
            <div className="p-4">
                <Alert variant="destructive">
                    <AlertDescription>
                        Failed to load apps: {error.message}
                    </AlertDescription>
                </Alert>
            </div>
        );
    }

    return (
        <div className="container mx-auto p-6">
            <header className="mb-8">
                <h1 className="text-3xl font-bold">Device Applications</h1>
                <p className="text-gray-500 mt-2">
                    {apps.length} application{apps.length !== 1 ? 's' : ''} found
                </p>
            </header>

            <AppList apps={apps} deviceId={deviceId} />
        </div>
    );
}
