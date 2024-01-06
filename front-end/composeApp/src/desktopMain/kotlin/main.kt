@file:OptIn(ExperimentalCoroutinesApi::class)

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import kotlinx.coroutines.*
import java.net.HttpURLConnection


@OptIn(ExperimentalMaterial3Api::class)
fun main() = application {

    val socket = SocketManager.getClient().connect()

    Window(onCloseRequest = ::exitApplication) {
        App(this.window, socket)
    }
}

