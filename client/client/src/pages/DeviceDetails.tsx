import { useParams } from 'react-router-dom'
import { useDeviceApps } from '@/hooks/useDeviceApps'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AppList } from '@/components/app/app-list'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function DeviceDetails() {
    const { deviceId } = useParams<{ deviceId: string }>()

    const { data: apps, isLoading, error } = useDeviceApps(deviceId!)

    if (isLoading) return <LoadingSpinner />

    if (error) {
        return (
            <div className="p-4">
                <Alert variant="destructive">
                    <AlertDescription>
                        Failed to load apps: {(error as Error).message}
                    </AlertDescription>
                </Alert>
            </div>
        )
    }

    if (!apps) return null

    return (
        <div className="container mx-auto p-6">
            <header className="mb-8">
                <h1 className="text-3xl font-bold">Device Applications</h1>
                <p className="text-gray-500 mt-2">
                    {apps.length} application{apps.length !== 1 ? 's' : ''} found
                </p>
            </header>

            <AppList apps={apps} deviceId={deviceId!} />
        </div>
    )
}