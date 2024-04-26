import {Device, ProcessID, Script, SendMessage, Session} from "frida";

export class InjectionManager {
    loadedScripts: Script[] = [];

    async unload_scripts(): Promise<void> {
        try {
            await Promise.all(this.loadedScripts.map(async (script) => {
                if (script.isDestroyed) {
                    console.warn("Script has already been destroyed.");
                    return;
                }

                await script.unload();
                console.log("Script unloaded successfully.");
            }));

            // Clear the array after unloading all scripts
            this.loadedScripts = [];
        } catch (error) {
            console.error("Error unloading scripts:", error);
        }
    }

    async run_app(device: Device, appName: string): Promise<ProcessID> {
        const pid = await device.spawn(appName);
        await device.resume(pid);
        return pid;
    }


    async handleApp(
        device: Device,
        scriptSource: string,
        appName: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void,
        event: 'attach' | 'launch'
    ) {
        const pid = event === 'launch' ? await this.run_app(device, appName) : appName;

        try {
            const session = await device.attach(pid);
            await this.createAndLoadScript(
                session,
                scriptSource,
                onScriptDestroyed,
                onNewMessage
            )
        } catch (e) {
            console.log(e);
        }
    }

    async attach(
        device: Device,
        scriptSource: string,
        appProcessId: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void
    ) {
        await this.handleApp(device, scriptSource, appProcessId, onScriptDestroyed, onNewMessage, 'attach');
    }

    async launch(
        device: Device,
        scriptSource: string,
        appName: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void
    ) {
        await this.handleApp(device, scriptSource, appName, onScriptDestroyed, onNewMessage, 'launch');
    }

    private async createAndLoadScript(
        session: Session,
        scriptSource: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void
    ): Promise<Script | undefined> {
        try {
            const script = await session.createScript(scriptSource);
            this.loadedScripts.push(script);

            script.message.connect((message: SendMessage) => {
                onNewMessage(message.payload);
            });

            script.destroyed.connect(onScriptDestroyed);

            await script.load();

            onNewMessage('[*] Script loaded');
            return script;
        } catch (e) {
            console.log(e);
            throw e;
        }
    }

}