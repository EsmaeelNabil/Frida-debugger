import { useQuery, useQueryClient } from 'react-query';
import { useSocket } from './useSocket.js';

export function useDevices() {
    const { emitEvent } = useSocket();
    const queryClient = useQueryClient();

    const { data: devices = [], isLoading, error } = useQuery(
        'devices',
        () => emitEvent('GET_DEVICES'),
        {
            onSuccess: (newDevices) => {
                // Pre-fetch device details for better UX
                newDevices.forEach(device => {
                    queryClient.prefetchQuery(
                        ['device', device.id],
                        () => emitEvent('GET_ALL_APPS', device.id)
                    );
                });
            }
        }
    );

    return { devices, isLoading, error };
}