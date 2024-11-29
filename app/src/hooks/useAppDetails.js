import { useQuery } from 'react-query';
import { useSocket } from './useSocket.js';

export function useAppDetails(deviceId, appName) {
    const { emitEvent } = useSocket();

    return useQuery(
        ['app', deviceId, appName],
        () => emitEvent('GET_APP', { deviceId, appName }),
        {
            enabled: !!deviceId && !!appName,
            staleTime: 10000,
        }
    );
}