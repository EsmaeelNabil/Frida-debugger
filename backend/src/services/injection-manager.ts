import {Device, Script, Session} from 'frida';
import {ScriptState} from '../types';
import {ErrorHandler} from './error-handler';

export class InjectionManager {
    private loadedScripts: Map<string, Script> = new Map();
    private scriptStates: Map<string, ScriptState> = new Map();

    async unloadScripts(): Promise<void> {
        try {
            // Using Array.from to convert Map entries to array
            const scripts = Array.from(this.loadedScripts);

            for (const [id, script] of scripts) {
                if (!script.isDestroyed) {
                    await script.unload();
                    this.scriptStates.get(id)!.status = 'stopped';
                }
            }
            this.loadedScripts.clear();
        } catch (error) {
            console.error("Error unloading scripts:", error);
            throw error;
        }
    }

    async runApp(device: Device, appName: string): Promise<number> {
        const pid = await device.spawn(appName);
        await device.resume(pid);
        return pid;
    }

    async attach(
        device: Device,
        scriptSource: string,
        appProcessId: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: any) => void
    ): Promise<string> {
        return this.handleApp(device, scriptSource, appProcessId, onScriptDestroyed, onNewMessage, 'attach');
    }

    async launch(
        device: Device,
        scriptSource: string,
        appName: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: any) => void
    ): Promise<string> {
        return this.handleApp(device, scriptSource, appName, onScriptDestroyed, onNewMessage, 'launch');
    }

    private async handleApp(
        device: Device,
        scriptSource: string,
        appIdentifier: string | number,
        onScriptDestroyed: () => void,
        onNewMessage: (message: any) => void,
        event: 'attach' | 'launch'
    ): Promise<string> {
        try {
            const pid = event === 'launch' ? await this.runApp(device, appIdentifier as string) : appIdentifier;
            const session = await device.attach(pid);
            const scriptId = await this.createAndLoadScript(session, scriptSource, onScriptDestroyed, onNewMessage);
            return scriptId;
        } catch (error) {
            throw ErrorHandler.handle(error as Error, 'InjectionManager.handleApp');
        }
    }

    private async createAndLoadScript(
        session: Session,
        scriptSource: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: any) => void
    ): Promise<string> {
        try {
            const script = await session.createScript(scriptSource);
            const scriptId = generateUniqueId();

            this.loadedScripts.set(scriptId, script);
            this.scriptStates.set(scriptId, {
                id: scriptId,
                status: 'running',
                startTime: new Date()
            });

            script.message.connect((message: any) => {
                onNewMessage(message.payload);
            });

            script.destroyed.connect(() => {
                this.scriptStates.get(scriptId)!.status = 'stopped';
                onScriptDestroyed();
            });

            await script.load();
            return scriptId;
        } catch (error) {
            throw ErrorHandler.handle(error as Error, 'InjectionManager.createAndLoadScript');
        }
    }

    async pauseScript(scriptId: string): Promise<void> {
        const script = this.loadedScripts.get(scriptId);
        if (script) {
            await script.post({type: 'pause'});
            this.scriptStates.get(scriptId)!.status = 'paused';
        }
    }

    async resumeScript(scriptId: string): Promise<void> {
        const script = this.loadedScripts.get(scriptId);
        if (script) {
            await script.post({type: 'resume'});
            this.scriptStates.get(scriptId)!.status = 'running';
        }
    }

    getScriptState(scriptId: string): ScriptState | undefined {
        return this.scriptStates.get(scriptId);
    }

    isHealthy(): boolean {
        return true; // Add actual health check logic
    }
}

function generateUniqueId(): string {
    return Math.random().toString(36).substr(2, 9);
}