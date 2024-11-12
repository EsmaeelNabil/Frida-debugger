// src/controllers/device-controller.ts
import {Server, Socket} from 'socket.io';
import {Device} from 'frida';
import {DeviceManagerService} from '../services/device-manager-service';
import {InjectionManager} from '../services/injection-manager';
import {ConnectionState} from '../services/connection-state';
import {DeviceMonitor} from '../services/device-monitor';
import {ErrorHandler} from '../services/error-handler';

export function initializeSocket(io: Server) {
    const connectionState = ConnectionState.getInstance();
    const deviceMonitor = DeviceMonitor.getInstance(io);

    io.on('connection', (socket: Socket) => {
        console.log(`Client connected: ${socket.id}`);

        connectionState.addClient(socket);
        const injectionManager = new InjectionManager();
        const deviceManager = new DeviceManagerService();

        // Set up device update monitoring
        deviceManager.setOnDeviceUpdateCallback((devices: Device[]) => {
            devices.forEach(device => {
                deviceMonitor.updateDeviceStatus(device, 'online');
            });
            socket.emit('DEVICES', devices);
        });

        // Basic server health check
        socket.on('IsServerUp', () => {
            socket.emit('IsServerUp', {
                isServerUp: true,
                timestamp: new Date().toISOString()
            });
        });

        // Device listing
        socket.on('GET_DEVICES', async () => {
            try {
                const devices = await deviceManager.getDevices();
                socket.emit('DEVICES', devices);
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'GET_DEVICES'));
            }
        });

        // Application management
        socket.on('GET_APPS', async (deviceId: string, appName?: string) => {
            try {
                if (appName) {
                    const app = await deviceManager.getApp(deviceId, appName);
                    socket.emit('APPS', app ? [app] : []);
                } else {
                    const apps = await deviceManager.getApps(deviceId);
                    socket.emit('APPS', apps);
                }
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'GET_APPS'));
            }
        });

        socket.on('GET_APP', async (data: { deviceId: string, appName: string }) => {
            try {
                console.log('GET_APP', data);
                const app = await deviceManager.getFullApp(data.deviceId, data.appName);
                socket.emit('APP', app);
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'GET_APP'));
            }
        });

        socket.on('GET_ALL_APPS', async (deviceId: string) => {
            try {
                console.log('GET_ALL_APPS', deviceId);
                const apps = await deviceManager.getAppsFull(deviceId);
                socket.emit('ALL_APPS', apps);
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'GET_ALL_APPS'));
            }
        });

        // Process management
        socket.on('GET_PROCESSES', async (deviceId: string) => {
            try {
                const processes = await deviceManager.getProcesses(deviceId);
                socket.emit('PROCESSES', processes);
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'GET_PROCESSES'));
            }
        });

        // Script management
        socket.on('UNLOAD_SCRIPTS', async () => {
            try {
                await injectionManager.unloadScripts();
                socket.emit('SCRIPTS_UNLOADED', {success: true});
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'UNLOAD_SCRIPTS'));
            }
        });

        // Launch and attach operations
        socket.on('LAUNCH', async (data: [string, string, string]) => {
            const [deviceId, appName, script] = data;
            try {
                deviceMonitor.incrementActiveProcesses(deviceId);
                await handleAttachOrLaunch(socket, deviceManager, injectionManager, deviceMonitor, deviceId, appName, script, 'launch');
            } catch (error) {
                deviceMonitor.decrementActiveProcesses(deviceId);
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'LAUNCH'));
            }
        });

        socket.on('ATTACH', async (data: [string, string, string]) => {
            try {
                const [deviceId, appName, script] = data;
                await handleAttachOrLaunch(socket, deviceManager, injectionManager, deviceMonitor, deviceId, appName, script, 'attach');
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'ATTACH'));
            }
        });

        socket.on('ATTACH_TO_APP', async (data: { deviceId: string, appName: string, script: string }) => {
            try {
                console.log('ATTACH_TO_APP', data);
                await handleAttachOrLaunch(
                    socket,
                    deviceManager,
                    injectionManager,
                    deviceMonitor,
                    data.deviceId,
                    data.appName,
                    data.script,
                    'attach'
                );
            } catch (error) {
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'ATTACH_TO_APP'));
            }
        });

        socket.on('LAUNCH_APP', async (data: { deviceId: string, appIdentifier: string, script: string }) => {
            try {
                console.log('LAUNCH_APP', data);
                deviceMonitor.incrementActiveProcesses(data.deviceId);
                await handleAttachOrLaunch(
                    socket,
                    deviceManager,
                    injectionManager,
                    deviceMonitor,
                    data.deviceId,
                    data.appIdentifier,
                    data.script,
                    'launch'
                );
            } catch (error) {
                deviceMonitor.decrementActiveProcesses(data.deviceId);
                socket.emit('ERROR', ErrorHandler.handle(error as Error, 'LAUNCH_APP'));
            }
        });

        // Device subscription
        socket.on('SUBSCRIBE_TO_DEVICE', (deviceId: string) => {
            connectionState.addDeviceSubscription(deviceId, socket.id);
            console.log(`Client ${socket.id} subscribed to device ${deviceId}`);
        });

        socket.on('UNSUBSCRIBE_FROM_DEVICE', (deviceId: string) => {
            connectionState.removeDeviceSubscription(deviceId, socket.id);
            console.log(`Client ${socket.id} unsubscribed from device ${deviceId}`);
        });

        // Handle disconnect
        socket.on('disconnect', () => {
            console.log(`Client disconnected: ${socket.id}`);
            connectionState.removeClient(socket.id);
        });
    });
}

// Helper function for attach/launch operations
async function handleAttachOrLaunch(
    socket: Socket,
    deviceManager: DeviceManagerService,
    injectionManager: InjectionManager,
    deviceMonitor: DeviceMonitor,
    deviceId: string,
    appName: string,
    script: string,
    event: 'attach' | 'launch'
) {
    const device = await deviceManager.getDevice(deviceId);
    if (!device) {
        throw new Error(`Device ${deviceId} not found`);
    }

    try {
        const scriptId = await injectionManager[event](
            device,
            script,
            appName,
            () => {
                socket.emit('ON_MESSAGE', 'Script destroyed');
                if (event === 'launch') {
                    deviceMonitor.decrementActiveProcesses(deviceId);
                }
            },
            (message: any) => socket.emit('ON_MESSAGE', message)
        );

        socket.emit('SCRIPT_LOADED', {
            scriptId,
            deviceId,
            appName,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        if (event === 'launch') {
            deviceMonitor.decrementActiveProcesses(deviceId);
        }
        throw error;
    }
}