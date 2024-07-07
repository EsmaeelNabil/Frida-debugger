import { Server, Socket } from 'socket.io';
import { Device } from 'frida';
import { DeviceManagerService } from '../services/device-manager-service';
import { InjectionManager } from '../services/injection-manager';


/**
 * Initializes the socket connection and defines the event handlers.
 * @param io - The socket.io server instance.
 */
export function initializeSocket(io: Server) {
  io.on('connection', (socket: Socket) => {
    console.log(`Client connected: ${socket.id}`);
    const injectionManager = new InjectionManager();
    const deviceManager = new DeviceManagerService();

    deviceManager.setOnDeviceUpdateCallback((devices: Device[]) => {
      socket.emit('DEVICES', devices);
    });

    socket.on('IsServerUp', () => {
      io.emit('IsServerUp', { isServerUp: true });
    });

    socket.on('GET_DEVICES', async () => {
      const devices = await deviceManager.getDevices();
      socket.emit('DEVICES', devices);
    });

    socket.on('GET_APPS', async (deviceId: string, appName?: string) => {
      if (appName) {
        const app = await deviceManager.getApp(deviceId, appName);
        socket.emit('APPS', [app]);
      } else {
        const apps = await deviceManager.getApps(deviceId);
        socket.emit('APPS', apps);
      }
    });

    socket.on('GET_APP', async (data) => {
      console.log('GET_APP', data);
      const app = await deviceManager.getFullApp(data.deviceId, data.appName);
      socket.emit('APP', app);
    });

    socket.on('GET_ALL_APPS', async (deviceId) => {
      console.log('GET_ALL_APPS', deviceId);
      const apps = await deviceManager.getAppsFull(deviceId);
      socket.emit('ALL_APPS', apps);
    });

    socket.on('GET_PROCESSES', async (deviceId: string) => {
      const processes = await deviceManager.getProcesses(deviceId);
      socket.emit('PROCESSES', processes);
    });

    socket.on('UNLOAD_SCRIPTS', async () => {
      await injectionManager.unload_scripts();
    });

    socket.on('LAUNCH', async (data: [string, string, string]) => {
      const [deviceId, appName, script] = data;
      handleAttachOrLaunch(socket, deviceManager, injectionManager, deviceId, appName, script, 'launch');
    });

    socket.on('ATTACH', async (data: [string, string, string]) => {
      const [deviceId, appName, script] = data;
      handleAttachOrLaunch(socket, deviceManager, injectionManager, deviceId, appName, script, 'attach');
    });

    socket.on('ATTACH_TO_APP', async (data) => {
      console.log('ATTACH_TO_APP', data);
      handleAttachOrLaunch(socket, deviceManager, injectionManager, data.deviceId, data.appName, data.script, 'attach');
    });

    socket.on('LAUNCH_APP', async (data) => {
      console.log('LAUNCH_APP', data);
      handleAttachOrLaunch(socket, deviceManager, injectionManager, data.deviceId, data.appIdentifier, data.script, 'launch');
    });

    
  });
}

/**
 * Handles attaching or launching the application.
 * @param socket - The socket instance.
 * @param deviceManager - The device manager service.
 * @param injectionManager - The injection manager.
 * @param deviceId - The device ID.
 * @param appName - The application name.
 * @param script - The script to inject.
 * @param event - The event type ('attach' or 'launch').
 */
async function handleAttachOrLaunch(
  socket: Socket,
  deviceManager: DeviceManagerService,
  injectionManager: InjectionManager,
  deviceId: string,
  appName: string,
  script: string,
  event: 'attach' | 'launch'
) {
  try {
    const device = await deviceManager.getDevice(deviceId);
    if (device) {
      await injectionManager[event](device, script, appName,
        () => socket.emit('ON_MESSAGE', 'Script destroyed'),
        (message: any) => socket.emit('ON_MESSAGE', message)
      );
    } else {
      socket.emit('ON_MESSAGE', `Device ${deviceId} not found`);
    }
  } catch (e) {
    socket.emit('ON_MESSAGE', `Error: ${e.message}`);
    console.error(e);
  }
}
