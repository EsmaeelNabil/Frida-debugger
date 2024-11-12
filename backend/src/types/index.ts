import { Device, Script } from 'frida';

export interface ClientState {
    socketId: string;
    connectedDevices: Set<string>;
    activeScripts: Map<string, ScriptState>;
    lastActivity: Date;
}

export interface ScriptState {
    id: string;
    status: 'running' | 'paused' | 'stopped';
    startTime: Date;
    lastError?: string;
}

export interface DeviceStatus {
    lastSeen: Date;
    status: 'online' | 'offline';
    activeProcesses: number;
    memoryUsage?: number;
    cpuUsage?: number;
}

export interface HealthStatus {
    server: boolean;
    deviceManager: boolean;
    injectionManager: boolean;
    timestamp: number;
}