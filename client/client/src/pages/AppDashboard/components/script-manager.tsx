// src/pages/AppDashboard/components/script-manager.tsx
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useToast } from '@/hooks/use-toast'
import { useSocket } from '@/context/SocketContext'
import { ScriptEditor } from './script-editor'
import { Play, Upload, StopCircle, FileCode2 } from 'lucide-react'

interface ScriptManagerProps {
    deviceId: string
    appName: string
    appIdentifier: string
    isRunning: boolean
}

const DEFAULT_SCRIPT = `// Script for interacting with the app
console.log('Script loaded');

// Add your code here
`

export function ScriptManager({
                                  deviceId,
                                  appName,
                                  appIdentifier,
                                  isRunning
                              }: ScriptManagerProps) {
    const [script, setScript] = useState(DEFAULT_SCRIPT)
    const [isEditorOpen, setIsEditorOpen] = useState(false)
    const { socket } = useSocket()
    const { toast } = useToast()

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0]
        if (!file) return

        try {
            const text = await file.text()
            setScript(text)
            toast({
                title: 'Script loaded',
                description: `Successfully loaded ${file.name}`,
            })
        } catch (error) {
            toast({
                title: 'Error loading script',
                description: error instanceof Error ? error.message : 'Failed to load script',
                variant: 'destructive',
            })
        }
    }

    const handleAttach = async () => {
        if (!socket) return

        try {
            socket.emit('ATTACH_TO_APP', { deviceId, appName, script })
            toast({
                title: 'Script attached',
                description: 'Successfully attached script to app',
            })
        } catch (error) {
            toast({
                title: 'Failed to attach script',
                description: error instanceof Error ? error.message : 'Unknown error occurred',
                variant: 'destructive',
            })
        }
    }

    const handleLaunch = async () => {
        if (!socket) return

        try {
            socket.emit('LAUNCH_APP', {
                deviceId,
                appIdentifier,
                script,
            })
            toast({
                title: 'App launched',
                description: 'Successfully launched app with script',
            })
        } catch (error) {
            toast({
                title: 'Failed to launch app',
                description: error instanceof Error ? error.message : 'Unknown error occurred',
                variant: 'destructive',
            })
        }
    }

    const handleUnload = async () => {
        if (!socket) return

        try {
            socket.emit('UNLOAD_SCRIPTS')
            toast({
                title: 'Scripts unloaded',
                description: 'Successfully unloaded all scripts',
            })
        } catch (error) {
            toast({
                title: 'Failed to unload scripts',
                description: error instanceof Error ? error.message : 'Unknown error occurred',
                variant: 'destructive',
            })
        }
    }

    return (
        <div className="space-y-6">
            <div className="space-y-4">
                <div className="flex items-center gap-4">
                    <Input
                        type="file"
                        accept=".js"
                        onChange={handleFileChange}
                        className="flex-1"
                    />
                    <Button
                        variant="outline"
                        onClick={() => setIsEditorOpen(true)}
                    >
                        <FileCode2 className="h-4 w-4 mr-2" />
                        Editor
                    </Button>
                </div>

                <div className="flex flex-wrap gap-3">
                    <Button
                        onClick={handleAttach}
                        disabled={!isRunning}
                    >
                        <Upload className="h-4 w-4 mr-2" />
                        Attach Script
                    </Button>
                    <Button
                        onClick={handleLaunch}
                        disabled={isRunning}
                    >
                        <Play className="h-4 w-4 mr-2" />
                        Launch App
                    </Button>
                    <Button
                        variant="destructive"
                        onClick={handleUnload}
                    >
                        <StopCircle className="h-4 w-4 mr-2" />
                        Unload Scripts
                    </Button>
                </div>
            </div>

            <ScriptEditor
                isOpen={isEditorOpen}
                onClose={() => setIsEditorOpen(false)}
                value={script}
                onChange={setScript}
            />
        </div>
    )
}