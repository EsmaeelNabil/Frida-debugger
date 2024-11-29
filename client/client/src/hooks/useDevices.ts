import {useQuery} from '@tanstack/react-query'
import {useSocket} from '@/context/SocketContext'
import type {Device} from '@/types'

export function useDevices() {
    const {socket} = useSocket()

    return useQuery<Device[]>({
        queryKey: ['devices'],
        queryFn: () => {
            return new Promise((resolve, reject) => {
                if (!socket) {
                    reject(new Error('Socket not connected'))
                    return
                }

                socket.emit('GET_DEVICES')

                const handleDevices = (devices: Device[]) => {
                    socket.off('DEVICES', handleDevices)
                    socket.off('ERROR', handleError)
                    resolve(devices)
                }

                const handleError = (error: { message: string }) => {
                    socket.off('DEVICES', handleDevices)
                    socket.off('ERROR', handleError)
                    reject(new Error(error.message))
                }

                socket.on('DEVICES', handleDevices)
                socket.on('ERROR', handleError)

                // Timeout after 5 seconds
                setTimeout(() => {
                    socket.off('DEVICES', handleDevices)
                    socket.off('ERROR', handleError)
                    reject(new Error('Request timeout'))
                }, 5000)
            })
        },
        enabled: !!socket && socket.connected,
        staleTime: 1000 * 30, // Consider data fresh for 30 seconds
    })
}