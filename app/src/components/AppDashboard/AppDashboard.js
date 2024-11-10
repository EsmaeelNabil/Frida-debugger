import React, { useEffect, useCallback, useMemo, useState } from "react";
import { useSocket } from "../../context/SocketContext";
import { useParams } from "react-router-dom";
import { toaster } from "evergreen-ui";

import AppHeader from "./AppHeader";
import AppInformation from "./AppInformation";
import ScriptManagement from "./ScriptManagement";
import ScriptEditor from "./ScriptEditor";
import MessageViewer from "./MessageViewer";

const INITIAL_SCRIPT_TEMPLATE = (appName) => `
// Script for ${appName}
// Use send() function to communicate with the app

send('Hello from ${appName}!');
`.trim();

const AppDashboard = () => {
    const socket = useSocket();
    const { deviceId, appName } = useParams();

    // State
    const [appDetails, setAppDetails] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [messages, setMessages] = useState([]);
    const [searchQuery, setSearchQuery] = useState("");
    const [editorVisible, setEditorVisible] = useState(false);
    const [code, setCode] = useState(INITIAL_SCRIPT_TEMPLATE(appName));
    const [files, setFiles] = useState(null);

    // File handling
    useEffect(() => {
        if (!files || !files[0]) {
            setCode(INITIAL_SCRIPT_TEMPLATE(appName));
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const content = reader.result;
                setCode(content);
                toaster.success("File loaded successfully");
            } catch (error) {
                console.error("Error reading file:", error);
                toaster.danger("Failed to read file contents");
            }
        };

        reader.onerror = () => {
            toaster.danger("Error reading file");
        };

        try {
            reader.readAsText(files[0]);
        } catch (error) {
            console.error("Error initiating file read:", error);
            toaster.danger("Failed to load file");
        }
    }, [files, appName]);

    const handleFileChange = useCallback((files) => {
        console.log("Files selected:", files); // Debug log
        setFiles(files);
    }, []);

    // Socket event handlers
    useEffect(() => {
        if (!socket) return;

        const handleAppData = (data) => {
            setAppDetails(data);
            setIsLoading(false);
        };

        const handleMessage = (data) => {
            if (data != null) {
                const messageStr = typeof data === 'object' ? JSON.stringify(data) : String(data);
                setMessages(prev => [...prev, messageStr]);
            }
        };

        socket.emit("GET_APP", { deviceId, appName });
        socket.on("APP", handleAppData);
        socket.on("ON_MESSAGE", handleMessage);

        return () => {
            socket.off("APP", handleAppData);
            socket.off("ON_MESSAGE", handleMessage);
        };
    }, [socket, deviceId, appName]);

    // Action Handlers
    const handleAttachToApp = useCallback(() => {
        try {
            socket.emit("ATTACH_TO_APP", { deviceId, appName, script: code });
            toaster.success("Script attached successfully");
        } catch (error) {
            console.error("Attach error:", error);
            toaster.danger("Failed to attach script");
        }
    }, [socket, deviceId, appName, code]);

    const handleLaunchApp = useCallback(() => {
        try {
            socket.emit("LAUNCH_APP", {
                deviceId,
                appIdentifier: appDetails?.identifier,
                script: code,
            });
            toaster.success("App launched with script");
        } catch (error) {
            console.error("Launch error:", error);
            toaster.danger("Failed to launch app");
        }
    }, [socket, deviceId, appDetails?.identifier, code]);

    const handleUnloadScripts = useCallback(() => {
        try {
            socket.emit("UNLOAD_SCRIPTS");
            toaster.success("Scripts unloaded");
        } catch (error) {
            console.error("Unload error:", error);
            toaster.danger("Failed to unload scripts");
        }
    }, [socket]);

    const handleClearMessages = useCallback(() => {
        setMessages([]);
        toaster.notify("Messages cleared");
    }, []);

    // Loading state
    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-screen bg-gray-50">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4" />
                    <p className="text-gray-600">Loading dashboard...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-50">
            <AppHeader
                appName={appName}
                appIcon={appDetails?.parameters?.icons?.[0]}
                status={appDetails?.pid ? 'running' : 'stopped'}
            />

            <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
                <AppInformation
                    appDetails={appDetails}
                    appName={appName}
                    isRunning={Boolean(appDetails?.pid)}
                />

                <ScriptManagement
                    onFileChange={handleFileChange}
                    onOpenEditor={() => setEditorVisible(true)}
                    onAttach={handleAttachToApp}
                    onLaunch={handleLaunchApp}
                    onUnload={handleUnloadScripts}
                    isAttachDisabled={!appDetails?.pid}
                />

                <MessageViewer
                    messages={messages}
                    searchQuery={searchQuery}
                    onSearchChange={setSearchQuery}
                    onClear={handleClearMessages}
                />

                <ScriptEditor
                    isShown={editorVisible}
                    onClose={() => setEditorVisible(false)}
                    code={code}
                    onCodeChange={setCode}
                />
            </main>
        </div>
    );
};

export default AppDashboard;