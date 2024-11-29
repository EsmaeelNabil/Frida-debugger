import {useState, useEffect} from 'react'
import {useParams} from 'react-router-dom'
import {Alert, AlertDescription} from '@/components/ui/alert'
import {Tabs, TabsContent, TabsList, TabsTrigger} from '@/components/ui/tabs'
import {Card} from '@/components/ui/card'
import {LoadingSpinner} from '@/components/ui/loading-spinner'
import {ScriptManager} from './components/script-manager'
import {MessageViewer} from './components/message-viewer'
import {AppInfo} from './components/app-info'
import {useSocket} from '@/context/SocketContext'
import type {Application} from '@/types'
import IconBuffer from "@/components/ui/icon-buffer.tsx";

export default function AppDashboard() {
    const {deviceId, appName} = useParams<{ deviceId: string; appName: string }>()
    const [app, setApp] = useState<Application | null>(null)
    const [messages, setMessages] = useState<string[]>([])
    const [isLoading, setIsLoading] = useState(true)
    const [error, setError] = useState<Error | null>(null)
    const {socket} = useSocket()

    useEffect(() => {
        if (!socket || !deviceId || !appName) return

        setIsLoading(true)
        socket.emit('GET_APP', {deviceId, appName})

        const handleApp = (data: Application) => {
            setApp(data)
            setIsLoading(false)
        }

        const handleError = (err: Error) => {
            setError(err)
            setIsLoading(false)
        }

        const handleMessage = (message: string) => {
            setMessages(prev => [...prev, message])
        }

        socket.on('APP', handleApp)
        socket.on('ERROR', handleError)
        socket.on('ON_MESSAGE', handleMessage)

        return () => {
            socket.off('APP', handleApp)
            socket.off('ERROR', handleError)
            socket.off('ON_MESSAGE', handleMessage)
        }
    }, [socket, deviceId, appName])

    if (isLoading) return <LoadingSpinner/>

    if (error) {
        return (
            <div className="p-4">
                <Alert variant="destructive">
                    <AlertDescription>
                        Failed to load app details: {error.message}
                    </AlertDescription>
                </Alert>
            </div>
        )
    }

    if (!app) return null

    return (
        <div className="container mx-auto p-6">
            <header className="mb-8">
                <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-lg">
                        {app.parameters.icons?.[0] && (
                            <IconBuffer icon={app.parameters.icons[0]}/>
                        )}
                    </div>
                    <div>
                        <h1 className="text-3xl font-bold">{app.name}</h1>
                        <p className="text-gray-500">{app.identifier}</p>
                    </div>
                </div>
            </header>

            <Tabs defaultValue="script" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="script">Script Management</TabsTrigger>
                    <TabsTrigger value="info">App Information</TabsTrigger>
                    <TabsTrigger value="messages">Messages</TabsTrigger>
                </TabsList>

                <TabsContent value="script" className="space-y-4">
                    <Card className="p-6">
                        <ScriptManager
                            deviceId={deviceId!}
                            appName={appName!}
                            appIdentifier={app.identifier}
                            isRunning={Boolean(app.pid)}
                        />
                    </Card>
                </TabsContent>

                <TabsContent value="info">
                    <Card className="p-6">
                        <AppInfo app={app}/>
                    </Card>
                </TabsContent>

                <TabsContent value="messages">
                    <Card className="p-6">
                        <MessageViewer messages={messages}/>
                    </Card>
                </TabsContent>
            </Tabs>
        </div>
    )
}

