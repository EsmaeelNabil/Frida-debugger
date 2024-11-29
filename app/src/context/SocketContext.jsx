import {createContext, useEffect, useState, useCallback} from 'react';
import {io} from 'socket.io-client';
import {useToast} from '@radix-ui/react-toast';

export const SocketContext = createContext(null);

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'ws://localhost:3002';
const RECONNECTION_ATTEMPTS = 3;
const RECONNECTION_DELAY = 2000;

export function SocketProvider({children}) {
    const [socket, setSocket] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const {toast} = useToast();

    const connect = useCallback(() => {
        const newSocket = io(SOCKET_URL, {
            reconnectionAttempts: RECONNECTION_ATTEMPTS,
            reconnectionDelay: RECONNECTION_DELAY,
            timeout: 5000,
        });

        newSocket.on('connect', () => {
            setIsConnected(true);
            toast({
                title: 'Connected to server',
                description: 'Successfully established connection',
                variant: 'success',
            });
        });

        newSocket.on('disconnect', () => {
            setIsConnected(false);
            toast({
                title: 'Disconnected from server',
                description: 'Connection lost. Attempting to reconnect...',
                variant: 'warning',
            });
        });

        newSocket.on('connect_error', (error) => {
            toast({
                title: 'Connection Error',
                description: error.message,
                variant: 'destructive',
            });
        });

        newSocket.on('ERROR', (error) => {
            toast({
                title: 'Server Error',
                description: error.message,
                variant: 'destructive',
            });
        });

        setSocket(newSocket);

        return () => {
            newSocket.close();
        };
    }, [toast]);

    useEffect(() => {
        const cleanup = connect();
        return cleanup;
    }, [connect]);

    const contextValue = {
        socket,
        isConnected,
        connect,
    };

    return (
        <SocketContext.Provider value={contextValue}>
            {children}
        </SocketContext.Provider>
    );
}