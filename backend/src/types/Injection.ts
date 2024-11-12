import {Device} from "frida";

export interface InjectionManager {
    attach(
        device: Device,
        script: string,
        appName: string,
        onDestroyed: () => void,
        onMessage: (message: any) => void
    ): Promise<string>;

    launch(
        device: Device,
        script: string,
        appName: string,
        onDestroyed: () => void,
        onMessage: (message: any) => void
    ): Promise<string>;

    unloadScripts(): Promise<void>;
}