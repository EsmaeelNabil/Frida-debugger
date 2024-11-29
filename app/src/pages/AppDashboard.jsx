import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { useAppDetails } from '@/hooks/useAppDetails.js';
import { useSocket } from '@/hooks/useSocket.js';
import { Alert, AlertDescription } from '@/components/ui/alert.jsx';
import LoadingSpinner from '@/components/common/LoadingSpinner.jsx';
import ScriptManager from '@/components/scripts/ScriptManager.jsx';
import MessageViewer from '@/components/messages/MessageViewer.jsx';

export default function AppDashboard() {
    const { deviceId, appName } = useParams();
    const { data: app, isLoading, error } = useAppDetails(deviceId, appName);
    const [messages, setMessages] = useState([]);
    const { socket } = useSocket();

    useEffect(() => {
        if (!socket) return;

        const handleMessage = (message) => {
            setMessages(prev => [...prev, message]);
        };

        socket.on('ON_MESSAGE', handleMessage);

        return () => {
            socket.off('ON_MESSAGE', handleMessage);
        };
    }, [socket]);

    const handleClearMessages = useCallback(() => {
        setMessages([]);
    }, []);

    if (isLoading) return <LoadingSpinner />;

    if (error) {
        return (
            <div className="p-4">
                <Alert variant="destructive">
                    <AlertDescription>
                        Failed to load app details: {error.message}
                    </AlertDescription>
                </Alert>
            </div>
        );
    }

    return (
        <div className="container mx-auto p-6">
            <header className="mb-8">
                <div className="flex items-center space-x-4">
                    {app?.parameters?.icons?.[0] && (
                        <img
                            src={`data:image/${app.parameters.icons[0].format};base64,${app.parameters.icons[0].image}`}
                            alt={appName}
                            className="w-12 h-12"
                        />
                    )}
                    <div>
                        <h1 className="text-3xl font-bold">{appName}</h1>
                        <p className="text-gray-500">
                            {app?.identifier} {app?.pid ? `(PID: ${app.pid})` : '(Not Running)'}
                        </p>
                    </div>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-6">
                    <section className="bg-white rounded-lg p-6 shadow-sm">
                        <h2 className="text-xl font-semibold mb-4">Script Management</h2>
                        <ScriptManager
                            deviceId={deviceId}
                            appName={appName}
                            appIdentifier={app?.identifier}
                        />
                    </section>

                    <section className="bg-white rounded-lg p-6 shadow-sm">
                        <h2 className="text-xl font-semibold mb-4">App Information</h2>
                        <dl className="grid grid-cols-2 gap-4">
                            <div>
                                <dt className="text-gray-500">Build</dt>
                                <dd>{app?.parameters?.build || 'N/A'}</dd>
                            </div>
                            <div>
                                <dt className="text-gray-500">Version</dt>
                                <dd>{app?.parameters?.version || 'N/A'}</dd>
                            </div>
                            <div>
                                <dt className="text-gray-500">Target SDK</dt>
                                <dd>{app?.parameters?.targetSdk || 'N/A'}</dd>
                            </div>
                            <div>
                                <dt className="text-gray-500">User</dt>
                                <dd>{app?.parameters?.user || 'N/A'}</dd>
                            </div>
                        </dl>
                    </section>
                </div>

                <section className="bg-white rounded-lg p-6 shadow-sm">
                    <h2 className="text-xl font-semibold mb-4">Messages</h2>
                    <MessageViewer
                        messages={messages}
                        onClear={handleClearMessages}
                    />
                </section>
            </div>
        </div>
    );
}