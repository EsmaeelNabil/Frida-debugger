import { Device, ProcessID, Script, SendMessage, Session } from "frida";

export class InjectionManager {
  private loadedScripts: Script[] = [];

  /**
   * Unloads all loaded scripts.
   */
  async unload_scripts(): Promise<void> {
    try {
      await Promise.all(this.loadedScripts.map(async (script) => {
        if (!script.isDestroyed) {
          await script.unload();
          console.log("Script unloaded successfully.");
        }
      }));
      this.loadedScripts = [];
    } catch (error) {
      console.error("Error unloading scripts:", error);
    }
  }

  /**
   * Runs an application on the device.
   * @param device - The device.
   * @param appName - The application name.
   * @returns The process ID of the running application.
   */
  async run_app(device: Device, appName: string): Promise<ProcessID> {
    const pid = await device.spawn(appName);
    await device.resume(pid);
    return pid;
  }

  private async handleApp(
    device: Device,
    scriptSource: string,
    appIdentifier: string | ProcessID,
    onScriptDestroyed: () => void,
    onNewMessage: (message: string) => void,
    event: 'attach' | 'launch'
  ) {
    const pid = event === 'launch' ? await this.run_app(device, appIdentifier as string) : appIdentifier;
    try {
      const session = await device.attach(pid);
      await this.createAndLoadScript(session, scriptSource, onScriptDestroyed, onNewMessage);
    } catch (e) {
      onNewMessage('[*] ' + e.message);
      console.error("Error handling app:", e);
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
      console.error("Error creating and loading script:", e);
      throw e;
    }
  }
}
