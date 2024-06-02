import androidx.compose.ui.window.application
import kotlinx.coroutines.*
import java.io.File


fun main() = application {
    val appPath = getAppPath()

    FridaApp(onCloseRequest = ::exitApplication)
//    NodeProcessManager(
//        nodeCommand = "/Users/esmaeelmoustafa/Pdev/Frida-debugger/backend/node_modules/.bin/ts-node",
//        scriptPath = "/Users/esmaeelmoustafa/Pdev/Frida-debugger/backend/src/index.ts",
//        workingDirectory = "/Users/esmaeelmoustafa/Pdev/Frida-debugger/backend/src/"
//    ).start()
}

fun getAppPath(): String {
    val path = File(
        NodeProcessManager::class.java.protectionDomain.codeSource.location.toURI()
    ).parentFile.parentFile.path
    return "$path/Resources/YourNodeProject"
}


class NodeProcessManager(
    private val nodeCommand: String,
    private val scriptPath: String,
    private val workingDirectory: String
) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun start() {
        startAndMonitorNodeProcess()

        // Keep the main application running
        println("Kotlin desktop application is running.")
    }

    private fun startAndMonitorNodeProcess() {
        scope.launch {
            while (isActive) {
                val command = listOf(nodeCommand, scriptPath)
                val workingDir = File(workingDirectory)

                try {
                    val processBuilder = ProcessBuilder(command).directory(workingDir)
                    val process = processBuilder.start()

                    // Capture and print the output
                    captureOutput(process)

                    // Wait for the process to complete
                    val exitCode = process.waitFor()
                    println("Process exited with code $exitCode")

                    // Restart the process if it exits with a non-zero code
                    if (exitCode != 0) {
                        println("Restarting process...")
                    }

                } catch (e: Exception) {
                    e.printStackTrace()
                }

                // Delay before restarting to avoid a rapid retry loop
                delay(1000)
            }
        }
    }

    private fun captureOutput(process: Process) {
        scope.launch {
            process.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { println("OUTPUT: $it") }
            }
        }

        scope.launch {
            process.errorStream.bufferedReader().useLines { lines ->
                lines.forEach { println("ERROR: $it") }
            }
        }
    }
}