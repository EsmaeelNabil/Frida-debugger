import { useContext, useCallback } from 'react';
import { SocketContext } from '@/context/SocketContext.jsx';

export function useSocket() {
    const socket = useContext(SocketContext);

    const emitEvent = useCallback((eventName, data) => {
        return new Promise((resolve, reject) => {
            if (!socket) {
                reject(new Error('Socket not connected'));
                return;
            }

            socket.emit(eventName, data);
            socket.once(eventName, resolve);
            socket.once('ERROR', reject);

            // Cleanup after 5 seconds to prevent memory leaks
            setTimeout(() => {
                socket.off(eventName, resolve);
                socket.off('ERROR', reject);
                reject(new Error('Socket timeout'));
            }, 5000);
        });
    }, [socket]);

    return { socket, emitEvent };
}
