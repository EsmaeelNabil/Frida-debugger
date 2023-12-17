import {Application, Device, DeviceManager, getDeviceManager, Process} from 'frida';
import {Scope} from 'frida/dist/device';

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

        this.deviceManager.added.connect(this.onAdded);
        this.deviceManager.removed.connect(this.onRemoved);
        this.deviceManager.changed.connect(this.onChanged);

        process.on('SIGTERM', this.stop);
        process.on('SIGINT', this.stop);

        this.forceUpdateDevices();
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
                const applications = await device.enumerateApplications({scope: Scope.Metadata});
                return applications;
            }
        } catch (e) {
            console.error(e);
            return [];
        }
        return [];
    }

    async getProcesses(deviceId: string): Promise<Process[]> {
        const device = this.devices.find((d) => d.id === deviceId);

        try {
            if (device) {
                const processes = await device.enumerateProcesses({scope: Scope.Metadata});
                return processes;
            }
        } catch (e) {
            console.error(e);
            return [];
        }
        return [];
    }


    private onAdded(device: Device): void {
        console.log(`Device added: ${device.id}`);
        this.devices.push(device);
        this.onDevicesUpdated();
    }

    private onRemoved(device: Device): void {
        console.log(`Device removed: ${device.id}`);
        this.devices = this.devices.filter((d) => d.id !== device.id);
        this.onDevicesUpdated();
    }

    private onChanged(): void {
        console.log('Device changed');
        this.onDevicesUpdated();
    }

    private stop(): void {
        this.deviceManager?.added.disconnect(this.onAdded);
        this.deviceManager?.removed.disconnect(this.onRemoved);
        this.deviceManager?.changed.disconnect(this.onChanged);
    }
}