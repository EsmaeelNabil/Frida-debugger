import { Socket } from 'socket.io';
import { ClientState, ScriptState } from '../types';

export class ConnectionState {
    private static instance: ConnectionState;
    private clients: Map<string, ClientState> = new Map();
    private deviceSubscriptions: Map<string, Set<string>> = new Map();

    private constructor() {}

    static getInstance(): ConnectionState {
        if (!ConnectionState.instance) {
            ConnectionState.instance = new ConnectionState();
        }
        return ConnectionState.instance;
    }

    addClient(socket: Socket): void {
        this.clients.set(socket.id, {
            socketId: socket.id,
            connectedDevices: new Set(),
            activeScripts: new Map(),
            lastActivity: new Date()
        });
    }

    removeClient(socketId: string): void {
        const client = this.clients.get(socketId);
        if (client) {
            client.connectedDevices.forEach(deviceId => {
                this.removeDeviceSubscription(deviceId, socketId);
            });
            this.clients.delete(socketId);
        }
    }

    addDeviceSubscription(deviceId: string, socketId: string): void {
        if (!this.deviceSubscriptions.has(deviceId)) {
            this.deviceSubscriptions.set(deviceId, new Set());
        }
        this.deviceSubscriptions.get(deviceId)?.add(socketId);
        this.clients.get(socketId)?.connectedDevices.add(deviceId);
    }

    removeDeviceSubscription(deviceId: string, socketId: string): void {
        this.deviceSubscriptions.get(deviceId)?.delete(socketId);
        this.clients.get(socketId)?.connectedDevices.delete(deviceId);
        if (this.deviceSubscriptions.get(deviceId)?.size === 0) {
            this.deviceSubscriptions.delete(deviceId);
        }
    }

    getDeviceSubscribers(deviceId: string): Set<string> {
        return this.deviceSubscriptions.get(deviceId) || new Set();
    }

    updateClientActivity(socketId: string): void {
        const client = this.clients.get(socketId);
        if (client) {
            client.lastActivity = new Date();
        }
    }

    updateScriptState(socketId: string, deviceId: string, scriptState: ScriptState): void {
        const client = this.clients.get(socketId);
        if (client) {
            client.activeScripts.set(deviceId, scriptState);
        }
    }

    getClientState(socketId: string): ClientState | undefined {
        return this.clients.get(socketId);
    }
}