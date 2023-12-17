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

import {Device, Script, SendMessage, Session} from "frida";

export class InjectionManager {
    loadedScripts: Script[] = [];

    async attach(device: Device,
                 scriptSource: string,
                 appProcessId: string,
                 onScriptDestroyed: () => void,
                 onNewMessage: (message: string) => void,
    ) {

        const session = await device.attach(appProcessId);
        await this.createAndLoadScript(
            session,
            scriptSource,
            onScriptDestroyed,
            onNewMessage
        )
    }

    async launch(device: Device,
                 scriptSource: string,
                 appName: string,
                 onScriptDestroyed: () => void,
                 onNewMessage: (message: string) => void,
    ) {

        const pid = await device.spawn(appName);
        const session = await device.attach(pid);
        await this.createAndLoadScript(
            session,
            scriptSource,
            onScriptDestroyed,
            onNewMessage
        )

        await device.resume(pid);
    }

    private async createAndLoadScript(
        session: Session,
        scriptSource: string,
        onScriptDestroyed: () => void,
        onNewMessage: (message: string) => void,
    ): Promise<Script> {
        const script = await session.createScript(scriptSource);
        this.loadedScripts.push(script);

        script.message.connect((message: SendMessage) => {
            onNewMessage(message.payload);
        });

        script.destroyed.connect(onScriptDestroyed);

        await script.load();

        onNewMessage('[*] Script loaded');
        return script;
    }

}