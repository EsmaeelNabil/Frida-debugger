import {Card, CardHeader, CardContent} from '@/components/ui/card'
import {Badge} from '@/components/ui/badge'
import IconBuffer from '@/components/ui/icon-buffer'
import type {Application} from '@/types'

interface AppCardProps {
    app: Application
    onClick: () => void
}

export function AppCard({app, onClick}: AppCardProps) {
    console.log('app', app)
    return (
        <Card
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={onClick}
        >
            <CardHeader className="flex flex-row items-center space-x-4 pb-2">
                <div className="w-10 h-10">
                    {app.parameters.icons?.[0] && (
                        <IconBuffer icon={app.parameters.icons[0]}/>
                    )}
                </div>
                <div>
                    <h3 className="font-semibold">{app.name}</h3>
                    <p className="text-sm text-gray-500">{app.identifier}</p>
                </div>
            </CardHeader>
            <CardContent>
                <div className="flex gap-2 flex-wrap">
                    <Badge variant={app.pid ? 'default' : 'secondary'}>
                        {app.pid ? 'Running' : 'Stopped'}
                    </Badge>
                    {app.pid > 0 && (
                        <Badge variant="outline">PID: {app.pid}</Badge>
                    )}
                </div>
            </CardContent>
        </Card>
    )
}