import type { Socket } from 'socket.io-client'
import type { Application, Device } from '@/types'

export interface ServerToClientEvents {
    connect: () => void
    disconnect: () => void
    DEVICES: (devices: Device[]) => void
    ALL_APPS: (apps: Application[]) => void
    APP: (app: Application) => void
    ERROR: (error: { message: string }) => void
    ON_MESSAGE: (message: string) => void
    SCRIPT_LOADED: (data: { scriptId: string; deviceId: string; appName: string; timestamp: string }) => void
    SCRIPTS_UNLOADED: (data: { success: boolean }) => void
}

export interface ClientToServerEvents {
    GET_DEVICES: () => void
    GET_ALL_APPS: (deviceId: string) => void
    GET_APP: (data: { deviceId: string; appName: string }) => void
    ATTACH_TO_APP: (data: { deviceId: string; appName: string; script: string }) => void
    LAUNCH_APP: (data: { deviceId: string; appIdentifier: string; script: string }) => void
    UNLOAD_SCRIPTS: () => void
    IsServerUp: () => void
}

export type AppSocket = typeof Socket