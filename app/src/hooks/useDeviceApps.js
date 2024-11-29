import { useQuery } from 'react-query';
import { useSocket } from './useSocket.js';

export function useDeviceApps(deviceId) {
    const { emitEvent } = useSocket();

    return useQuery(
        ['device', deviceId, 'apps'],
        () => emitEvent('GET_ALL_APPS', deviceId),
        {
            enabled: !!deviceId,
            staleTime: 30000, // Consider data fresh for 30 seconds
        }
    );
}
