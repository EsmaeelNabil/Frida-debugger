import { Badge } from '@/components/ui/badge'
import type { Application } from '@/types'

interface AppInfoProps {
    app: Application
}

export function AppInfo({ app }: AppInfoProps) {
    const details = [
        { label: 'Identifier', value: app.identifier },
        { label: 'Status', value: app.pid ? 'Running' : 'Stopped' },
        { label: 'PID', value: app.pid || 'N/A' },
        { label: 'Build', value: app.parameters.build || 'N/A' },
        { label: 'Version', value: app.parameters.version || 'N/A' },
        { label: 'Target SDK', value: app.parameters.targetSdk || 'N/A' },
        { label: 'Data Directory', value: app.parameters.dataDir || 'N/A' },
        { label: 'User', value: app.parameters.user || 'N/A' },
    ]

    return (
        <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {details.map(({ label, value }) => (
                    <div
                        key={label}
                        className="p-4 rounded-lg bg-muted"
                    >
                        <dt className="text-sm font-medium text-muted-foreground">
                            {label}
                        </dt>
                        <dd className="mt-1 text-sm">
                            {label === 'Status' ? (
                                <Badge variant={value === 'Running' ? 'default' : 'secondary'}>
                                    {value}
                                </Badge>
                            ) : (
                                value
                            )}
                        </dd>
                    </div>
                ))}
            </div>
        </div>
    )
}