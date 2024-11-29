import { useDevices } from '@/hooks/useDevices'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { DeviceCard } from '@/components/device/device-card'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function Home() {
    const { data: devices, isLoading, error } = useDevices()

    if (isLoading) return <LoadingSpinner />

    if (error) {
        return (
            <div className="p-4">
                <Alert variant="destructive">
                    <AlertDescription>
                        Failed to load devices: {(error as Error).message}
                    </AlertDescription>
                </Alert>
            </div>
        )
    }

    return (
        <div className="container mx-auto p-6">
            <header className="mb-8">
                <h1 className="text-3xl font-bold">Connected Devices</h1>
                <p className="text-gray-500 mt-2">
                    {devices?.length || 0} device{devices?.length !== 1 ? 's' : ''} found
                </p>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {devices?.map((device) => (
                    <DeviceCard key={device.id} device={device} />
                ))}
            </div>
        </div>
    )
}
