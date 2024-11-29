import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error
import { io, Socket } from 'socket.io-client'
import { useToast } from '@/hooks/use-toast'
import type { ServerToClientEvents, ClientToServerEvents } from '@/types/socket'

interface SocketContextValue {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    socket: Socket<ServerToClientEvents, ClientToServerEvents> | null
    isConnected: boolean
    connect: () => void
}

const SocketContext = createContext<SocketContextValue | null>(null)

interface SocketProviderProps {
    children: ReactNode
}

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'ws://localhost:3002'

export function SocketProvider({ children }: SocketProviderProps) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    const [socket, setSocket] = useState<Socket<ServerToClientEvents, ClientToServerEvents> | null>(null)
    const [isConnected, setIsConnected] = useState(false)
    const { toast } = useToast()

    const connect = () => {
        try {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            const newSocket: Socket<ServerToClientEvents, ClientToServerEvents> = io(SOCKET_URL, {
                transports: ['websocket'],
                autoConnect: true,
                reconnection: true,
                reconnectionAttempts: 3,
                reconnectionDelay: 1000,
            })

            newSocket.on('connect', () => {
                setIsConnected(true)
                toast({
                    title: 'Connected to server',
                    description: 'Successfully established connection',
                })
            })

            newSocket.on('disconnect', () => {
                setIsConnected(false)
                toast({
                    title: 'Disconnected from server',
                    description: 'Connection lost. Attempting to reconnect...',
                    variant: 'destructive',
                })
            })

            newSocket.on('connect_error', (error: { message: never }) => {
                toast({
                    title: 'Connection Error',
                    description: error.message,
                    variant: 'destructive',
                })
            })

            setSocket(newSocket)

            return () => {
                newSocket.disconnect()
            }
        } catch (error) {
            console.error('Socket initialization error:', error)
            toast({
                title: 'Connection Error',
                description: 'Failed to initialize socket connection',
                variant: 'destructive',
            })
        }
    }

    useEffect(() => {
        const cleanup = connect()
        return () => {
            cleanup?.()
        }
    }, [])

    return (
        <SocketContext.Provider value={{ socket, isConnected, connect }}>
            {children}
        </SocketContext.Provider>
    )
}

export function useSocket() {
    const context = useContext(SocketContext)
    if (!context) {
        throw new Error('useSocket must be used within a SocketProvider')
    }
    return context
}
