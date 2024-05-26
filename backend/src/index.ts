import cors from "cors";
import express from "express";
import {Application, Process} from "frida";
import {Device} from "frida/dist/device";
import http from "http";
import {Server} from "socket.io";
import {DeviceManagerService} from "./DeviceManagerService";
import {InjectionManager} from "./InjectionManager";

const app = express();
let scriptsMap = new Map<string, string>();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "http://localhost:3000",
        methods: ["GET", "POST"],
    },
});

app.use(cors());

server.listen(3002, () => {
    console.log("Listening on port 3002");
});

function getScriptNamesSeparatedByComma(inputString: string): string[] {
    // Check if the string contains a comma
    if (inputString.includes(',')) {
        // Split the string into an array of words
        return inputString.split(',').map(word => word.trim());
    } else {
        // If there is no comma, return a list containing the single word
        return [inputString.trim()];
    }
}


function getScriptsFromCache(scriptNames: string) {
    const scripts = getScriptNamesSeparatedByComma(scriptNames);
    let finalScript = "";
    if (scripts && scripts.length != 0) {
        scripts.forEach((value) => {
            finalScript = appendScript(finalScript, scriptsMap.get(value));
        })
    }
    return finalScript;
}

function appendScript(original: string | null, addMe: string): string {
    // Check if the original string is not null, undefined, or empty
    if (original !== null && original.trim() !== '') {
        // Append a new line and the other string
        return `${original}\n${addMe}`;
    } else {
        // If the original string is null, undefined, or empty, simply return the other string
        return addMe;
    }
}


io.on("connection", (socket) => {
    console.log(socket.id)
    let injectionManager: InjectionManager = new InjectionManager();

    let deviceManager = new DeviceManagerService();
    deviceManager.setOnDeviceUpdateCallback((devices: Device[]) => {
        // todo : Fix me
        socket.emit("DEVICES", devices);
    });

    function handleAttachOrLaunch(deviceId: any, appName: any, script: any, event: String) {
        deviceManager.getDevice(deviceId).then((device: Device) => {
            // @ts-ignore
            injectionManager[event](
                device,
                script,
                appName,
                () => {
                    socket.emit("ON_MESSAGE", 'script destroyed');
                },
                (message: any) => {
                    socket.emit("ON_MESSAGE", message);
                })
                .catch((e: any) => {
                    socket.emit("ON_MESSAGE", `process not found ${JSON.stringify(e)}`);
                    console.log(e);
                });
        }).catch(e => console.log(e));
    }


    socket.on("IsServerUp", async () => {
        io.emit("IsServerUp", {isServerUp: true});
    });

    socket.on("GET_DEVICES", () => {
        deviceManager.getDevices().then((devices) => {
            socket.emit("DEVICES", devices);
        });
    });

    socket.on("GET_APPS", async (deviceId, appName?) => {
        try {
            if (appName) {
                deviceManager.getApp(deviceId, appName).then((app: Application | undefined) => {
                    socket.emit("APPS", [app]);
                });
            } else {
                deviceManager.getApps(deviceId).then((apps: Application[]) => {
                    socket.emit("APPS", apps);
                });
            }
        } catch (e) {
            console.log(e);
        }

    });

    socket.on("GET_PROCESSES", async (deviceId) => {
        deviceManager.getProcesses(deviceId).then((apps: Process[]) => {
            socket.emit("PROCESSES", apps);
        });
    });

    socket.on("UNLOAD_SCRIPTS", async () => {
        await injectionManager.unload_scripts();
    });

    socket.on("RUN_APP", async (data: [string, string]) => {
        const [deviceId, appName] = data;
        let device = await deviceManager.getDevice(deviceId);

        await injectionManager.run_app(device, appName).then((pid) => {
            socket.emit("ON_MESSAGE", `App ${appName} is running now with id : ${pid}`);
        }).catch(e => console.log(e));
    });

    socket.on("ATTACH", async (data: [string, string, string]) => {
        const [deviceId, appName, script] = data;
        handleAttachOrLaunch(deviceId, appName, script, 'attach');
    });
});


process.once("SIGUSR2", function () {
    process.kill(process.pid, "SIGUSR2");
});

process.on("SIGINT", function () {
    // Gracefully stop the server
    console.log("Shutting down...");
    server.close(() => {
        console.log("Server stopped");
        process.exit(0);
    });
});