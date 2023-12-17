@file:OptIn(ExperimentalCoroutinesApi::class)

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import kotlinx.coroutines.*


fun main() = application {

    val socket = SocketManager.getClient().connect()

    Window(onCloseRequest = ::exitApplication) {
        App(this.window, socket)
    }
}

