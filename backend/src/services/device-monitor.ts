import { Device } from 'frida';
import { Server } from 'socket.io';
import { ConnectionState } from './connection-state';
import { DeviceStatus } from '../types';

export class DeviceMonitor {
    private static instance: DeviceMonitor;
    private io: Server;
    private connectionState: ConnectionState;
    private deviceStatus: Map<string, DeviceStatus> = new Map();

    private constructor(io: Server) {
        this.io = io;
        this.connectionState = ConnectionState.getInstance();
        this.startPerformanceMonitoring();
    }

    static getInstance(io: Server): DeviceMonitor {
        if (!DeviceMonitor.instance) {
            DeviceMonitor.instance = new DeviceMonitor(io);
        }
        return DeviceMonitor.instance;
    }

    private startPerformanceMonitoring(): void {
        setInterval(() => {
            this.deviceStatus.forEach((status, deviceId) => {
                if (status.status === 'online') {
                    this.updateDeviceMetrics(deviceId);
                }
            });
        }, 5000); // Update every 5 seconds
    }

    private async updateDeviceMetrics(deviceId: string): Promise<void> {
        const status = this.deviceStatus.get(deviceId);
        if (status) {
            // Here you could add actual device metrics collection
            // This is a placeholder for demonstration
            status.memoryUsage = Math.random() * 100;
            status.cpuUsage = Math.random() * 100;

            this.notifyDeviceMetrics(deviceId);
        }
    }

    private notifyDeviceMetrics(deviceId: string): void {
        const status = this.deviceStatus.get(deviceId);
        if (status) {
            const subscribers = this.connectionState.getDeviceSubscribers(deviceId);
            subscribers.forEach(socketId => {
                this.io.to(socketId).emit('DEVICE_METRICS', {
                    deviceId,
                    metrics: {
                        memoryUsage: status.memoryUsage,
                        cpuUsage: status.cpuUsage,
                        activeProcesses: status.activeProcesses
                    },
                    timestamp: new Date().toISOString()
                });
            });
        }
    }

    updateDeviceStatus(device: Device, status: 'online' | 'offline'): void {
        this.deviceStatus.set(device.id, {
            lastSeen: new Date(),
            status,
            activeProcesses: 0
        });

        const subscribers = this.connectionState.getDeviceSubscribers(device.id);
        subscribers.forEach(socketId => {
            this.io.to(socketId).emit('DEVICE_STATUS_UPDATE', {
                deviceId: device.id,
                status,
                timestamp: new Date().toISOString()
            });
        });
    }

    incrementActiveProcesses(deviceId: string): void {
        const status = this.deviceStatus.get(deviceId);
        if (status) {
            status.activeProcesses++;
            this.notifyDeviceLoad(deviceId);
        }
    }

    decrementActiveProcesses(deviceId: string): void {
        const status = this.deviceStatus.get(deviceId);
        if (status && status.activeProcesses > 0) {
            status.activeProcesses--;
            this.notifyDeviceLoad(deviceId);
        }
    }

    private notifyDeviceLoad(deviceId: string): void {
        const status = this.deviceStatus.get(deviceId);
        if (status) {
            const subscribers = this.connectionState.getDeviceSubscribers(deviceId);
            subscribers.forEach(socketId => {
                this.io.to(socketId).emit('DEVICE_LOAD_UPDATE', {
                    deviceId,
                    activeProcesses: status.activeProcesses,
                    timestamp: new Date().toISOString()
                });
            });
        }
    }
}