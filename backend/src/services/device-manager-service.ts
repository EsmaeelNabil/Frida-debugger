import { Application, Device, DeviceManager, getDeviceManager, Process, Scope } from 'frida';

export interface OnDeviceUpdateCallback {
  (devices: Device[]): void;
}

export class DeviceManagerService {
  private deviceManager: DeviceManager;
  private devices: Device[] = [];
  private onDeviceUpdateCallback: OnDeviceUpdateCallback | null = null;

  constructor() {
    this.deviceManager = getDeviceManager();
    this.deviceManager.added.connect(this.onDeviceAdded.bind(this));
    this.deviceManager.removed.connect(this.onDeviceRemoved.bind(this));
    this.deviceManager.changed.connect(this.onDevicesChanged.bind(this));
    this.forceUpdateDevices().catch(console.error);
  }

  private onDeviceAdded(device: Device) {
    console.log(`Device added: ${device.id}`);
    this.devices.push(device);
    this.onDevicesUpdated();
  }

  private onDeviceRemoved(device: Device) {
    console.log(`Device removed: ${device.id}`);
    this.devices = this.devices.filter(d => d.id !== device.id);
    this.onDevicesUpdated();
  }

  private onDevicesChanged() {
    console.log('Devices changed');
    this.onDevicesUpdated();
  }

  private onDevicesUpdated() {
    if (this.onDeviceUpdateCallback) {
      this.onDeviceUpdateCallback(this.devices);
    }
  }

  async forceUpdateDevices() {
    this.devices = await this.deviceManager.enumerateDevices();
    this.onDevicesUpdated();
  }

  setOnDeviceUpdateCallback(callback: OnDeviceUpdateCallback): void {
    this.onDeviceUpdateCallback = callback;
  }

  async getDevice(deviceId: string): Promise<Device | undefined> {
    if (this.devices.length === 0) {
      await this.forceUpdateDevices();
    }
    return this.devices.find(d => d.id === deviceId);
  }

  async getDevices(): Promise<Device[]> {
    if (this.devices.length === 0) {
      await this.forceUpdateDevices();
    }
    return this.devices;
  }

  async getApps(deviceId: string): Promise<Application[]> {
    const device = await this.getDevice(deviceId);
    if (device) {
      try {
        return await device.enumerateApplications({ scope: Scope.Metadata });
      } catch (e) {
        console.error(e);
      }
    }
    return [];
  }

  async getApp(deviceId: string, appName: string): Promise<Application | undefined> {
    const device = await this.getDevice(deviceId);
    if (device) {
      try {
        const applications = await device.enumerateApplications({ scope: Scope.Minimal });
        return applications.find(app => app.name.toLowerCase().includes(appName.toLowerCase()));
      } catch (e) {
        console.error(e);
      }
    }
  }

  async getProcesses(deviceId: string): Promise<Process[]> {
    const device = await this.getDevice(deviceId);
    if (device) {
      try {
        return await device.enumerateProcesses({ scope: Scope.Metadata });
      } catch (e) {
        console.error(e);
      }
    }
    return [];
  }
}
