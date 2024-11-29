import { useQuery } from '@tanstack/react-query'
import { useSocket } from '@/context/SocketContext'
import type { Application } from '@/types'

export function useDeviceApps(deviceId: string) {
    const { socket } = useSocket()

    return useQuery<Application[]>({
        queryKey: ['device', deviceId, 'apps'],
        queryFn: () => {
            return new Promise((resolve, reject) => {
                if (!socket) {
                    reject(new Error('Socket not connected'))
                    return
                }
                socket.emit('GET_ALL_APPS', deviceId)
                socket.once('ALL_APPS', resolve)
                socket.once('ERROR', reject)

                setTimeout(() => {
                    socket.off('ALL_APPS')
                    socket.off('ERROR')
                    reject(new Error('Request timeout'))
                }, 5000)
            })
        },
        enabled: !!socket && !!deviceId
    })
}