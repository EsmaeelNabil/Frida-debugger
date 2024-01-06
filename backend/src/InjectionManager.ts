/*
 socket.on("START_ATTACH", async (deviceId, appProcessId) => {
        let device = await deviceManager.getDevice(deviceId);
        const session = await device.attach(appProcessId)
        console.log('[*] Process Attached');
        const script = await session.createScript(load_stetho);
        script.message.connect((message : SendMessage) => {
            console.log('[*] Message:', message.payload);
            socket.emit("ON_MESSAGE", message.payload);
        });
        await script.load();
        console.log('[*] Script loaded');

    });
* */

import { Device, ProcessID, Script, SendMessage, Session } from "frida";

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
        device.resume(pid);
        return pid;
    }

    async attach(device: Device,
        scriptSource: string,
        appProcessId: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void,
    ) {

        try {
            const session = await device.attach(appProcessId);
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

    async launch(device: Device,
        scriptSource: string,
        appName: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void,
    ) {

        const pid = await this.run_app(device, appName);

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

    private async createAndLoadScript(
        session: Session,
        scriptSource: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void,
    ): Promise<Script> {
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
            return undefined;
        }
    }

}