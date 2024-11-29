import { useState, useCallback } from 'react';
import { useSocket } from '@/hooks/useSocket.js';
import { Button } from '@/components/ui/button.jsx';
import { Input } from '@/components/ui/input.jsx';
import { useToast } from '@/components/ui/use-toast';
import { Play, Pause, Upload, StopCircle, Edit } from 'lucide-react';
import ScriptEditor from './ScriptEditor.jsx';

export default function ScriptManager({ deviceId, appName, appIdentifier }) {
    const [script, setScript] = useState('');
    const [isEditorOpen, setIsEditorOpen] = useState(false);
    const { emitEvent } = useSocket();
    const { toast } = useToast();

    const handleFileChange = async (e) => {
        try {
            const file = e.target.files[0];
            if (!file) return;

            const content = await file.text();
            setScript(content);
            toast({
                title: 'Script loaded',
                description: `Successfully loaded ${file.name}`,
            });
        } catch (error) {
            toast({
                title: 'Error loading script',
                description: error.message,
                variant: 'destructive',
            });
        }
    };

    const handleAttach = useCallback(async () => {
        try {
            await emitEvent('ATTACH_TO_APP', { deviceId, appName, script });
            toast({
                title: 'Script attached',
                description: 'Successfully attached script to app',
            });
        } catch (error) {
            toast({
                title: 'Attachment failed',
                description: error.message,
                variant: 'destructive',
            });
        }
    }, [deviceId, appName, script, emitEvent, toast]);

    const handleLaunch = useCallback(async () => {
        try {
            await emitEvent('LAUNCH_APP', {
                deviceId,
                appIdentifier,
                script,
            });
            toast({
                title: 'App launched',
                description: 'Successfully launched app with script',
            });
        } catch (error) {
            toast({
                title: 'Launch failed',
                description: error.message,
                variant: 'destructive',
            });
        }
    }, [deviceId, appIdentifier, script, emitEvent, toast]);

    const handleUnload = useCallback(async () => {
        try {
            await emitEvent('UNLOAD_SCRIPTS');
            toast({
                title: 'Scripts unloaded',
                description: 'Successfully unloaded all scripts',
            });
        } catch (error) {
            toast({
                title: 'Unload failed',
                description: error.message,
                variant: 'destructive',
            });
        }
    }, [emitEvent, toast]);

    return (
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
                    <Edit className="h-4 w-4 mr-2" />
                    Open Editor
                </Button>
            </div>

            <div className="flex flex-wrap gap-3">
                <Button onClick={handleAttach}>
                    <Upload className="h-4 w-4 mr-2" />
                    Attach Script
                </Button>
                <Button onClick={handleLaunch}>
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

            <ScriptEditor
                isOpen={isEditorOpen}
                onClose={() => setIsEditorOpen(false)}
                initialCode={script}
                onSave={setScript}
            />
        </div>
    );
}