import { Application, Device, DeviceManager, getDeviceManager, Process } from 'frida';
import { Scope } from 'frida/dist/device';

export interface OnDeviceUpdateCallback {
    (devices: Device[]): void;
}

export class DeviceManagerService {
    private deviceManager: DeviceManager | null = null;
    private devices: Device[] = [];
    private onDeviceUpdateCallback: OnDeviceUpdateCallback | null = null;

    private onDevicesUpdated() {
        if (this.onDeviceUpdateCallback) {
            this.onDeviceUpdateCallback(this.devices);
        }
    }

    constructor() {
        this.deviceManager = getDeviceManager();

        this.deviceManager.added.connect((device) => {
            console.log(`Device added: ${device.id}`);
            console.log(this)
            if (this.devices === undefined) {
                return
            }
            this.devices.push(device);
            this.onDevicesUpdated();
        }
        );

        this.deviceManager.removed.connect((device) => {
            console.log(`Device removed: ${device.id}`);
            console.log(this)
            if (this.devices === undefined) {
                return
            }
            this.devices = this.devices.filter((d) => d.id !== device.id);
            this.onDevicesUpdated();
        });

        this.deviceManager.changed.connect(() => {
            console.log('Device changed');
            this.onDevicesUpdated();
        });

        this.forceUpdateDevices().then(() => { });
    }

    async forceUpdateDevices() {
        this.devices = await this.deviceManager.enumerateDevices();
        this.onDevicesUpdated();
    }

    setOnDeviceUpdateCallback(callback: OnDeviceUpdateCallback): void {
        this.onDeviceUpdateCallback = callback;
    }

    async getDevice(deviceId: String): Promise<Device> {
        const devices = await this.getDevices()
        return devices.find((d) => d.id === deviceId);
    }

    async getDevices(): Promise<Device[]> {
        if (this.devices.length == 0) {
            await this.forceUpdateDevices()
        }
        return this.devices;
    }

    async getApps(deviceId: string): Promise<Application[]> {
        const device = this.devices.find((d) => d.id === deviceId);

        try {
            if (device) {
                const applications = await device.enumerateApplications({ scope: Scope.Metadata });
                return applications;
            }
        } catch (e) {
            console.error(e);
            return [];
        }
        return [];
    }

    async getApp(deviceId: string, appName: string): Promise<Application> {
        const device = this.devices.find((d) => d.id === deviceId);
        try {
            if (device) {
                const applications = await device.enumerateApplications({ scope: Scope.Minimal });
                const app = applications.find((app) => {
                    return app.name.toLowerCase().includes(appName.toLowerCase());
                });
                return app;
            }
        } catch (e) {
            console.error(e);
            return undefined;
        }
    }

    async getProcesses(deviceId: string): Promise<Process[]> {
        const device = this.devices.find((d) => d.id === deviceId);

        try {
            if (device) {
                const processes = await device.enumerateProcesses({ scope: Scope.Metadata });
                return processes;
            }
        } catch (e) {
            console.error(e);
            return [];
        }
        return [];
    }
}