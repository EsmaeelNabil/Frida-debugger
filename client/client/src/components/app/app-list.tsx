import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { AppCard } from './app-card'
import type { Application } from '@/types'

interface AppListProps {
    apps: Application[]
    deviceId: string
}

export function AppList({ apps, deviceId }: AppListProps) {
    const [searchQuery, setSearchQuery] = useState('')
    const navigate = useNavigate()

    const filteredApps = apps.filter(app =>
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.identifier.toLowerCase().includes(searchQuery.toLowerCase())
    )

    return (
        <div className="space-y-4">
            <Input
                placeholder="Search apps..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="max-w-sm"
            />

            <ScrollArea className="h-[70vh]">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {filteredApps.map(app => (
                        <AppCard
                            key={app.pid + Math.random()}
                            app={app}
                            onClick={() => navigate(`/app/${deviceId}/${app.name}`)}
                        />
                    ))}
                </div>
            </ScrollArea>
        </div>
    )
}
