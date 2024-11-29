export interface Device {
    impl: {
        id: string,
        name: string,
        type: 'local' | 'usb' | 'remote'
    }
}

export interface AppIcon {
    format: string
    width: number
    height: number
    image: ArrayBuffer
}

export interface AppParameters {
    icons?: AppIcon[]
    build?: string
    version?: string
    targetSdk?: string
    dataDir?: string
    ppid?: number
    user?: string
}

export interface Application {
    name: string
    identifier: string
    pid: number
    parameters: AppParameters
}

export interface ScriptState {
    id: string
    status: 'running' | 'paused' | 'stopped'
    startTime: Date
    lastError?: string
}

export interface DeviceStatus {
    lastSeen: Date
    status: 'online' | 'offline'
    activeProcesses: number
    memoryUsage?: number
    cpuUsage?: number
}